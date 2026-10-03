/**
 * SimPass (简幻通) — New API task plugin
 *
 * SimPass is a WeChat-mini-program identity verification system for game
 * servers. Two contracts matter, and they are different:
 *
 * INBOUND — how a caller addresses this plugin (documented at
 * https://txpass-2.apifox.cn, OpenAI Chat Completions compatible):
 *
 *   POST <gateway>/simpass/v1/chat/completions
 *   Authorization: Bearer <New API token>
 *   { "model": "<one of three>", "messages": [{ "role": "user", "content": "<JSON string>" }] }
 *
 *   simpass-auth1       content { user_id, verify_code[, mc_username, mc_uuid, player_ip] }
 *                       -> { success: true, data: { code, msg, user_info } }
 *   simpass-otp-请求    content {} or { mc_uuid?, mc_username?, player_ip? }
 *                       -> { success: true, data: { otp_id, expires_in, status: "pending" } }
 *   simpass-otp-查询    content { otp_id }
 *                       -> { success: true, data: { status, user_id?, user_info? } }
 *                          status is pending | verified | rejected
 *
 *   The reply is a chat.completion whose choices[0].message.content is the JSON
 *   envelope above, serialized. Failures use
 *   { success: false, error: { message, type, code }, help }.
 *
 *   The documented route is POST /v1/chat/completions, but a plugin route may not
 *   claim it: the host rejects any plugin route that intersects a static route
 *   (router/plugin-router.go validatePlugin -> routeIntersectsStaticRoute), and
 *   /v1/chat/completions is New API's own relay endpoint. This plugin therefore
 *   serves the identical contract one segment deeper, under /simpass.
 *
 * UPSTREAM — the SimPass developer API (base URL https://pass.simpfun.cn), which
 * is what the plugin actually calls:
 *
 *   POST /api/dev/auth    body { uuid, user_id, verify_code[, mc_username, mc_uuid, player_ip] }
 *                         -> { code, msg, user_info }; code 200 means success
 *   GET  /api/dev/otp?uuid=<developer uuid>[&mc_uuid=][&mc_username=][&player_ip=]
 *                         -> { otp_id, expires_in }
 *   GET  /api/dev/otp?otp_id=<otp_id>
 *                         -> { status } while pending
 *                         -> { status: "verified", user_id, user_info } once verified
 *   Errors                HTTP 4xx/5xx, sometimes an HTML 500 page
 *
 *   POST /api/dev/auth is undocumented in the public SimPass pages; it was found
 *   by probing and is the endpoint behind the documented verify_code flow.
 *
 * This plugin addresses two upstream kinds, selected by the executing channel:
 *
 *   vendor   channel type 61, key = the SimPass developer UUID. Credentials ride
 *            in the JSON body (auth) or the query string (otp), never a header.
 *            The host injects ctx.apiKey for auth type api_key
 *            (relay/channel/task/jsplugin/auth.go).
 *   new_api  channel type 60, key = a token of the upstream gateway. The upstream
 *            is another New API with this plugin installed, so its chat route is
 *            addressed instead, with the channel key as a Bearer token
 *            (adaptor.go applyUpstreamCredentials). Declaring
 *            upstreams: ["new_api"] is what makes this bindable to type 60 at all
 *            (controller/channel.go rejects it otherwise).
 *
 * All three models answer within the submit call, so every task is immediately
 * terminal and nothing is ever polled. Two deliberate consequences:
 *
 *   - A business rejection (a wrong verify code, or an upstream code other than
 *     200) is reported as an immediate FAILURE. The host then renders the native
 *     route response normally -- the caller still gets HTTP 200 with the
 *     documented error envelope -- while billing is zeroed for that submission
 *     (relay/relay_task.go: finalQuota = 0 on an immediate failure).
 *   - The documented stream: true long poll (hold up to 60s until the player
 *     scans) cannot be reproduced here: plugin hooks are synchronous and cannot
 *     sleep, retry, or hold a connection. A caller polls simpass-otp-查询
 *     instead, which returns the current status at once.
 */

const DOC_URL = "https://txpass-2.apifox.cn";
const DEFAULT_BASE_URL = "https://pass.simpfun.cn";

const AUTH_PATH = "/api/dev/auth";
const OTP_PATH = "/api/dev/otp";
const QR_PATH = "/api/otp";

/** This plugin's own chat route, and the same path on an upstream gateway. */
const CHAT_PATH = "/simpass/v1/chat/completions";

const UPSTREAM_NEW_API = "new_api";

const MODEL_AUTH = "simpass-auth1";
const MODEL_OTP_CREATE = "simpass-otp-请求";
const MODEL_OTP_QUERY = "simpass-otp-查询";
const MODELS = [MODEL_AUTH, MODEL_OTP_CREATE, MODEL_OTP_QUERY];

/** Optional player fields, forwarded to the upstream only when supplied. */
const PLAYER_PARAMS = ["mc_username", "mc_uuid", "player_ip"];

export const meta = {
  apiVersion: 1,
  key: "simpass",
  name: "Simpass(星涵煦版)",
  icon: "text:SP",
  version: "0.0.1",
  author: { name: "星涵煦", url: "https://github.com/xinghanxu6666" },
  description: {
    en: "SimPass (JianHuanTong) WeChat identity verification, served as an OpenAI Chat Completions compatible endpoint",
    zh: "SimPass 简幻通微信身份验证，以 OpenAI Chat Completions 兼容接口对外提供服务",
  },
  baseUrl: DEFAULT_BASE_URL,
  auth: "api_key",
  // channelTypes is deliberately omitted. It declares legacy vendor channel
  // types only; the host rejects both the task plugin type (61) and the New API
  // type (60) here, because a task plugin binds through the channel's
  // task_plugin_key setting instead. SimPass has no legacy channel type.
  upstreams: ["vendor", "new_api"],
  models: MODELS,
  fetchMode: "per_task",
  routes: [
    {
      method: "POST",
      path: CHAT_PATH,
      type: "submit",
      action: "chat",
      decode: "decodeChat",
      render: "renderChat",
      models: MODELS,
    },
  ],
  usageSchema: {
    requests: {
      type: "number",
      unit: "count",
      description: { en: "Verification request unit price", zh: "验证请求单价" },
    },
  },
  usageExamples: [{ label: "One verification", facts: { requests: 1 } }],
};

// --- helpers -----------------------------------------------------------------

function trimmed(value) {
  return typeof value === "string" ? value.trim() : "";
}

function asObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value;
}

/**
 * True when the executing channel points at another New API gateway. A missing
 * or malformed ctx.upstream falls back to the vendor, which is what older hosts
 * that never inject the field need.
 */
function isGateway(ctx) {
  const upstream = (ctx || {}).upstream;
  if (!upstream || typeof upstream !== "object" || Array.isArray(upstream)) {
    return false;
  }
  return trimmed(upstream.kind) === UPSTREAM_NEW_API;
}

/** The declared machine identity wins over an alias mapped by the channel. */
function resolveModel(ctx) {
  const scope = ctx || {};
  return trimmed(scope.upstreamModel) || trimmed(scope.model);
}

function assertKnownModel(model) {
  if (MODELS.indexOf(model) === -1) {
    throw new Error(
      'SimPass does not serve model "' + model + '"; use ' + MODELS.join(", ")
    );
  }
  return model;
}

/** The channel key is the developer UUID (vendor) or a gateway token (new_api). */
function requireApiKey(ctx) {
  const key = trimmed((ctx || {}).apiKey);
  if (!key) {
    throw new Error(
      "SimPass needs the developer UUID as the channel key; set the Task Plugin channel key to your developer UUID"
    );
  }
  return key;
}

/** Channel base URL, tolerating a trailing slash or an already-included /api. */
function upstreamBase(ctx) {
  const scope = ctx || {};
  let base = trimmed(scope.baseUrl) || DEFAULT_BASE_URL;
  while (base.length > 1 && base.charAt(base.length - 1) === "/") {
    base = base.slice(0, -1);
  }
  // Only the vendor surface lives under /api, so a base URL that already ends
  // in /api is folded away for vendor calls only; a gateway base URL may
  // legitimately carry path segments of its own.
  if (!isGateway(scope) && base.length > 4 && base.slice(-4).toLowerCase() === "/api") {
    base = base.slice(0, -4);
  }
  return base;
}

/** The host already prefixes "Bearer " for a New API channel; fall back anyway. */
function gatewayAuth(ctx) {
  const header = trimmed((ctx || {}).authHeader);
  if (header) return header;
  return "Bearer " + requireApiKey(ctx);
}

function jsonHeaders(json) {
  const headers = { Accept: "application/json" };
  if (json) headers["Content-Type"] = "application/json";
  return headers;
}

function gatewayHeaders(ctx, json) {
  const headers = jsonHeaders(json);
  headers.Authorization = gatewayAuth(ctx);
  return headers;
}

function queryString(params) {
  const parts = [];
  const names = Object.keys(params);
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index];
    const raw = params[name];
    if (raw === undefined || raw === null) continue;
    const value = String(raw).trim();
    if (!value) continue;
    parts.push(encodeURIComponent(name) + "=" + encodeURIComponent(value));
  }
  return parts.join("&");
}

function httpStatus(response) {
  const status = response ? Number(response.statusCode) : NaN;
  return Number.isFinite(status) ? status : 0;
}

/** The upstream reports vendor errors as { "error": ... } or { code, msg }. */
function upstreamMessage(body) {
  const object = asObject(body);
  const error = object.error;
  if (typeof error === "string" && error.trim()) return error.trim();
  if (error && typeof error === "object") {
    const nested = trimmed(error.message);
    if (nested) return nested;
    try {
      return JSON.stringify(error);
    } catch (ignored) {
      return "";
    }
  }
  return trimmed(object.msg);
}

function requirePublicTaskId(ctx) {
  const value = trimmed((ctx || {}).publicTaskId);
  if (!value) throw new Error("SimPass requires the gateway public task id");
  return value;
}

// --- chat envelopes ----------------------------------------------------------

function successEnvelope(data) {
  return { success: true, data: data };
}

function failureEnvelope(message, code) {
  return {
    success: false,
    error: {
      message: message || "SimPass request failed",
      type: "upstream_error",
      code: code || "upstream_failed",
    },
    help: "请参考 API 文档: " + DOC_URL,
  };
}

function messageContent(body) {
  const messages = asObject(body).messages;
  if (!Array.isArray(messages) || messages.length === 0) {
    throw new Error("messages must be a non-empty array");
  }
  return asObject(messages[0]).content;
}

/** content is documented as a JSON string, but an object is accepted too. */
function contentParameters(content) {
  if (typeof content === "string") {
    const text = content.trim();
    if (!text) return {};
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (ignored) {
      throw new Error("content must be a valid JSON string");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("the content JSON must be an object");
    }
    return parsed;
  }
  if (content && typeof content === "object" && !Array.isArray(content)) {
    return content;
  }
  return {};
}

/** Reads the chat envelope a caller sent. */
function chatBody(ctx) {
  const body = (ctx || {}).body;
  if (!body || body.kind !== "json") {
    throw new Error("a JSON request body is required");
  }
  const value = body.value;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("the JSON request body must be an object");
  }
  return value;
}

/** Reads the chat envelope an upstream gateway answered with. */
function gatewayEnvelope(body) {
  const object = asObject(body);
  const choices = object.choices;
  if (!Array.isArray(choices) || choices.length === 0) {
    throw new Error("the upstream New API gateway response did not include choices");
  }
  const message = asObject(asObject(choices[0]).message);
  const text = trimmed(message.content);
  if (!text) {
    throw new Error("the upstream New API gateway response has an empty message content");
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (ignored) {
    throw new Error("the upstream New API gateway message content is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("the upstream New API gateway message content is not a JSON object");
  }
  return parsed;
}

/** The model a caller named, read back from the route request. */
function chatModel(ctx) {
  const body = (ctx || {}).body;
  const value = body && typeof body === "object" ? body.value : undefined;
  return trimmed(asObject(value).model);
}

function chatCompletion(taskId, model, created, envelope) {
  return {
    id: "chatcmpl-" + taskId,
    object: "chat.completion",
    created: created,
    model: model,
    choices: [
      {
        index: 0,
        message: { role: "assistant", content: JSON.stringify(envelope) },
        finish_reason: "stop",
      },
    ],
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
  };
}

export const native = {
  decodeChat: function (ctx) {
    const body = chatBody(ctx);
    const model = assertKnownModel(trimmed(body.model));
    if (typeof body.stream === "boolean" && body.stream) {
      // The host cannot hold a connection open for a plugin, so the documented
      // long poll is served as an immediate status instead of being silently
      // ignored. Callers poll simpass-otp-查询 for the same effect.
      if (model !== MODEL_OTP_QUERY) {
        throw new Error("stream is not supported on " + model + "; it is only meaningful on " + MODEL_OTP_QUERY);
      }
    }
    return {
      kind: "submit",
      model: model,
      action: model,
      requestBody: contentParameters(messageContent(body)),
    };
  },

  renderChat: function (ctx, task) {
    const view = asObject(task);
    const data = view.data;
    const envelope =
      data && typeof data === "object" && !Array.isArray(data) && typeof asObject(data).success === "boolean"
        ? data
        : failureEnvelope("SimPass did not return a usable result", "internal_error");
    return chatCompletion(
      trimmed(view.task_id),
      chatModel(ctx),
      view.created_at,
      envelope
    );
  },

  error: function (ctx, error) {
    const message =
      typeof error === "string" ? error.trim() : trimmed(error && error.message);
    return failureEnvelope(message, "format_error");
  },
};

// --- submit ------------------------------------------------------------------

function numericParameter(value, name) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  const text = trimmed(value);
  if (text && /^[0-9]+$/.test(text)) return Number(text);
  throw new Error(name + " must be a number");
}

function forwardedPlayers(source, target) {
  for (let index = 0; index < PLAYER_PARAMS.length; index += 1) {
    const name = PLAYER_PARAMS[index];
    if (Object.prototype.hasOwnProperty.call(source, name) && trimmed(source[name])) {
      target[name] = source[name];
    }
  }
  return target;
}

/** The chat envelope this plugin would send to an upstream gateway. */
function gatewayChatBody(model, parameters) {
  return {
    model: model,
    messages: [{ role: "user", content: JSON.stringify(parameters) }],
  };
}

export function buildSubmitRequest(ctx) {
  const scope = ctx || {};
  const model = assertKnownModel(resolveModel(scope));
  const parameters = asObject(scope.requestBody);

  if (isGateway(scope)) {
    return {
      url: upstreamBase(scope) + CHAT_PATH,
      method: "POST",
      headers: gatewayHeaders(scope, true),
      body: gatewayChatBody(model, parameters),
    };
  }

  if (model === MODEL_AUTH) {
    const body = {
      uuid: requireApiKey(scope),
      user_id: numericParameter(parameters.user_id, "user_id"),
      verify_code: numericParameter(parameters.verify_code, "verify_code"),
    };
    forwardedPlayers(parameters, body);
    return {
      url: upstreamBase(scope) + AUTH_PATH,
      method: "POST",
      headers: jsonHeaders(true),
      body: body,
    };
  }

  if (model === MODEL_OTP_CREATE) {
    const query = forwardedPlayers(parameters, { uuid: requireApiKey(scope) });
    return {
      url: upstreamBase(scope) + OTP_PATH + "?" + queryString(query),
      method: "GET",
      headers: jsonHeaders(false),
    };
  }

  const otpId = trimmed(parameters.otp_id);
  if (!otpId) throw new Error("otp_id must be a non-empty string");
  return {
    url: upstreamBase(scope) + OTP_PATH + "?" + queryString({ otp_id: otpId }),
    method: "GET",
    headers: jsonHeaders(false),
  };
}

export function parseSubmitResponse(ctx, response) {
  const scope = ctx || {};
  const status = httpStatus(response);
  const body = response ? response.body : null;
  assertKnownModel(resolveModel(scope));

  // A transport-level failure is not a business answer, so it becomes an HTTP
  // error rather than a fabricated envelope.
  if (status < 200 || status >= 300) {
    throw new Error(upstreamMessage(body) || ("SimPass returned HTTP " + status));
  }

  if (isGateway(scope)) {
    const envelope = gatewayEnvelope(body);
    const taskId = requirePublicTaskId(scope);
    if (envelope.success === false) {
      return {
        taskId: taskId,
        taskData: envelope,
        immediate: {
          status: "FAILURE",
          reason: trimmed(asObject(envelope.error).message) || "the upstream gateway reported a failure",
        },
      };
    }
    return {
      taskId: taskId,
      taskData: envelope,
      immediate: { status: "SUCCESS", progress: "100%" },
    };
  }

  const model = resolveModel(scope);
  const object = asObject(body);
  const taskId = requirePublicTaskId(scope);

  if (model === MODEL_AUTH) {
    const code = Number(object.code);
    if (Number.isFinite(code) && code !== 200) {
      const message = trimmed(object.msg) || "SimPass rejected the verification";
      return {
        taskId: taskId,
        taskData: failureEnvelope(message, "auth_error"),
        immediate: { status: "FAILURE", reason: message },
      };
    }
    return {
      taskId: taskId,
      taskData: successEnvelope(object),
      immediate: { status: "SUCCESS", progress: "100%" },
    };
  }

  if (model === MODEL_OTP_CREATE) {
    const otpId = trimmed(object.otp_id);
    if (!otpId) throw new Error("SimPass response did not include otp_id");
    const expiresIn = Number(object.expires_in);
    return {
      taskId: taskId,
      taskData: successEnvelope({
        otp_id: otpId,
        expires_in: Number.isFinite(expiresIn) ? expiresIn : null,
        status: "pending",
        verify_url: upstreamBase(scope) + QR_PATH + "?otp_id=" + encodeURIComponent(otpId),
      }),
      immediate: { status: "SUCCESS", progress: "100%" },
    };
  }

  const otpStatus = trimmed(object.status).toLowerCase();
  if (!otpStatus) throw new Error("SimPass OTP response is missing a status field");
  const data = { status: otpStatus };
  if (object.user_id !== undefined) data.user_id = object.user_id;
  if (object.user_info !== undefined) data.user_info = object.user_info;
  return {
    taskId: taskId,
    taskData: successEnvelope(data),
    immediate: { status: "SUCCESS", progress: "100%" },
  };
}

// --- polling -----------------------------------------------------------------
// Every model answers within the submit call, so no task is ever polled. The
// hooks still have to exist: fetchMode per_task makes buildQueryRequest a
// required export (pkg/jsplugin/registry.go requiredHooks).

export function buildQueryRequest(ctx) {
  assertKnownModel(resolveModel(ctx || {}));
  throw new Error("SimPass answers within the submit call and has no task to retrieve");
}

export function parseTaskResult(ctx, body, response) {
  return {
    status: "UNKNOWN",
    reason: "SimPass answers within the submit call and has no asynchronous task",
  };
}

// --- usage -------------------------------------------------------------------

export function extractUsage(ctx) {
  const scope = ctx || {};
  if (scope.usagePurpose === "billing_ratios") return null;
  return { requests: 1 };
}
