/**
 * SimPass (简幻通) — New API task plugin
 *
 * SimPass is a WeChat-mini-program identity verification system for game
 * servers. Developer API documentation:
 *   https://s.apifox.cn/2ee8388d-101e-4268-bfa5-412e8044675a
 *
 * This plugin addresses two upstream kinds, selected by the executing channel:
 *
 *   vendor   (channel type 61, key = the SimPass developer UUID)
 *     The upstream API surface is (base URL https://pass.simpfun.cn):
 *       Create OTP   GET /api/dev/otp?uuid=<developer uuid>[&mc_uuid=][&mc_username=][&player_ip=]
 *                    -> { otp_id, expires_in }
 *       Poll OTP     GET /api/dev/otp?otp_id=<otp_id>
 *                    -> { status }                                  while still pending
 *                    -> { status: "verified", user_id, user_info }   once verified
 *       User info    GET /api/dev/info?uuid=<developer uuid>&user_id=<user id>
 *                    -> { level, risky, create_time[, risk_details] }
 *       Errors       HTTP 400/401/403/404/500 with { "error": "<message>" }
 *     Credentials ride in the query string as uuid=, not in a header, so
 *     ctx.apiKey is placed in the query. The host injects ctx.apiKey for auth
 *     type api_key (relay/channel/task/jsplugin/auth.go).
 *
 *   new_api  (channel type 60, key = a token of the upstream gateway)
 *     The upstream is another New API gateway with this same plugin installed,
 *     so its own native routes are addressed instead, with the channel key sent
 *     as a Bearer token. The host injects ctx.authHeader as "Bearer <key>" and
 *     ctx.upstream.kind as "new_api" for that channel type
 *     (relay/channel/task/jsplugin/adaptor.go applyUpstreamCredentials):
 *       POST <gateway>/simpass/otp           -> task envelope incl. verify_url
 *       POST <gateway>/simpass/verify        -> completed result
 *       GET  <gateway>/simpass/task/<id>     -> status plus latest result
 *     Declaring upstreams: ["new_api"] is what makes this plugin bindable to a
 *     type-60 channel at all (controller/channel.go rejects it otherwise).
 *
 * Two upstream shapes share one plugin, selected by model:
 *
 *   simpass-otp     Asynchronous. Creates an OTP challenge and polls until the
 *                   player scans the QR code.
 *   simpass-验证    Synchronous. The user info lookup already is the answer, so
 *                   submit completes immediately and there is nothing to poll.
 *
 * Native routes exist because the generic task API cannot carry the answers
 * back: GET /v1/tasks/<id> returns only task_id, platform, status, progress,
 * fail_reason and timestamps, so the caller can neither build the QR payload
 * (the upstream otp_id is kept in private task data) nor read the verification
 * result. These routes render the upstream payload to the caller directly:
 *
 *   POST /simpass/otp            -> task envelope incl. verify_url
 *   POST /simpass/verify         -> verification result (immediate)
 *   GET  /simpass/task/:task_id  -> current status plus the latest upstream data
 *
 * All three require a New API token (Bearer) and are scoped to the calling
 * user. The upstream payload is returned under "result". When the task ran
 * against another gateway, that gateway's own envelope is unwrapped, so a
 * caller sees the same "result" shape in both topologies.
 *
 * Scope is deliberately narrow for 0.0.1: no Image/Video protocol and no
 * artifacts. The generic entry POST /v1/tasks/simpass keeps working.
 */

const DEFAULT_BASE_URL = "https://pass.simpfun.cn";
const OTP_PATH = "/api/dev/otp";
const INFO_PATH = "/api/dev/info";
const QR_PATH = "/api/otp";

/** Native route paths of this plugin, addressed on an upstream gateway. */
const GATEWAY_OTP_PATH = "/simpass/otp";
const GATEWAY_VERIFY_PATH = "/simpass/verify";
const GATEWAY_TASK_PATH = "/simpass/task/";

const UPSTREAM_NEW_API = "new_api";

const MODEL_OTP = "simpass-otp";
const MODEL_INFO = "simpass-验证";

/** The only terminal OTP status the upstream documents. */
const OTP_STATUS_VERIFIED = "verified";

/** Optional parameters of the OTP creation call, forwarded only when present. */
const OTP_OPTIONAL_PARAMS = ["mc_uuid", "mc_username", "player_ip"];

export const meta = {
  apiVersion: 1,
  key: "simpass",
  name: "Simpass(星涵煦版)",
  icon: "text:SP",
  version: "0.0.1",
  author: { name: "星涵煦", url: "https://github.com/xinghanxu6666" },
  description: {
    en: "SimPass (JianHuanTong) WeChat identity verification: create OTP challenges and look up player verification info",
    zh: "SimPass 简幻通微信身份验证：生成 OTP 认证并查询玩家验证信息",
  },
  baseUrl: DEFAULT_BASE_URL,
  auth: "api_key",
  channelTypes: [61],
  upstreams: ["vendor", "new_api"],
  models: [MODEL_OTP, MODEL_INFO],
  fetchMode: "per_task",
  routes: [
    {
      method: "POST",
      path: "/simpass/otp",
      type: "submit",
      action: "otp",
      decode: "decodeOtpSubmit",
      render: "renderOtpSubmit",
    },
    {
      method: "POST",
      path: "/simpass/verify",
      type: "submit",
      action: "verify",
      decode: "decodeVerifySubmit",
      render: "renderVerifySubmit",
    },
    {
      method: "GET",
      path: "/simpass/task/:task_id",
      type: "query",
      render: "renderTaskQuery",
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
  if (model !== MODEL_OTP && model !== MODEL_INFO) {
    throw new Error(
      'SimPass does not serve model "' + model + '"; use ' + MODEL_OTP + " or " + MODEL_INFO
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

function gatewayHeaders(ctx, json) {
  const headers = { Authorization: gatewayAuth(ctx), Accept: "application/json" };
  if (json) headers["Content-Type"] = "application/json";
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

function jsonHeaders() {
  return { Accept: "application/json" };
}

/** The upstream reports every failure as { "error": "<message>" }. */
function upstreamError(body) {
  const object = asObject(body);
  const error = object.error;
  if (typeof error === "string" && error.trim()) return error.trim();
  if (error && typeof error === "object") {
    const message = trimmed(error.message);
    if (message) return message;
    try {
      return JSON.stringify(error);
    } catch (ignored) {
      return "";
    }
  }
  return "";
}

function httpStatus(response) {
  const status = response ? Number(response.statusCode) : NaN;
  return Number.isFinite(status) ? status : 0;
}

function pollStatus(response) {
  const status = response ? Number(response.status) : NaN;
  return Number.isFinite(status) ? status : 0;
}

function requirePublicTaskId(ctx) {
  const value = trimmed((ctx || {}).publicTaskId);
  if (!value) throw new Error("SimPass requires the gateway public task id");
  return value;
}

// --- native route decoding ---------------------------------------------------

/** Native submit routes only ever accept a JSON object body. */
function jsonBody(ctx) {
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

/**
 * The route owns the model: whatever the caller puts in "model" is overwritten,
 * so a body cannot address a model the route was not declared for.
 */
function routedBody(ctx, model) {
  const value = jsonBody(ctx);
  const copy = {};
  const names = Object.keys(value);
  for (let index = 0; index < names.length; index += 1) {
    copy[names[index]] = value[names[index]];
  }
  copy.model = model;
  return copy;
}

/**
 * A result produced by another New API gateway is that gateway's own task
 * envelope. Unwrap it once so the caller sees the same payload whether the task
 * ran against the vendor or against an upstream gateway.
 */
function unwrapGatewayEnvelope(value) {
  const object = asObject(value);
  if (!trimmed(object.task_id) || !trimmed(object.status)) return value;
  const inner = object.result;
  if (!inner || typeof inner !== "object" || Array.isArray(inner)) return value;
  return inner;
}

/**
 * The host hands the renderer a TaskView: the public identity plus "data", the
 * latest persisted upstream snapshot. The upstream payload is nested under
 * "result" so a caller can branch on status without unpacking the task record.
 */
function renderTaskView(task) {
  const view = asObject(task);
  const rendered = {
    task_id: trimmed(view.task_id),
    status: trimmed(view.status),
    progress: trimmed(view.progress),
    created_at: view.created_at,
    finished_at: view.finished_at,
  };
  const reason = trimmed(view.fail_reason);
  if (reason) rendered.fail_reason = reason;
  const result = unwrapGatewayEnvelope(view.data);
  if (result && typeof result === "object" && !Array.isArray(result)) {
    rendered.result = result;
  }
  return rendered;
}

export const native = {
  decodeOtpSubmit: function (ctx) {
    return {
      kind: "submit",
      model: MODEL_OTP,
      action: "otp",
      requestBody: routedBody(ctx, MODEL_OTP),
    };
  },

  decodeVerifySubmit: function (ctx) {
    return {
      kind: "submit",
      model: MODEL_INFO,
      action: "verify",
      requestBody: routedBody(ctx, MODEL_INFO),
    };
  },

  renderOtpSubmit: function (ctx, task) {
    return renderTaskView(task);
  },

  renderVerifySubmit: function (ctx, task) {
    return renderTaskView(task);
  },

  renderTaskQuery: function (ctx, task) {
    return renderTaskView(task);
  },

  error: function (ctx, error) {
    const message =
      typeof error === "string" ? error.trim() : trimmed(error && error.message);
    return { error: message || "SimPass request failed" };
  },
};

// --- submit ------------------------------------------------------------------

/** The OTP call forwards only the optional player fields that were supplied. */
function otpParameters(requestBody) {
  const body = asObject(requestBody);
  const params = {};
  for (let index = 0; index < OTP_OPTIONAL_PARAMS.length; index += 1) {
    const name = OTP_OPTIONAL_PARAMS[index];
    if (Object.prototype.hasOwnProperty.call(body, name) && trimmed(body[name])) {
      params[name] = body[name];
    }
  }
  return params;
}

/** simpass-验证 accepts the player id the caller wants verified. */
function requireUserId(requestBody) {
  const body = asObject(requestBody);
  const raw = body.user_id;
  const value = typeof raw === "number" && Number.isFinite(raw) ? String(raw) : trimmed(raw);
  if (!value) {
    throw new Error("user_id must be a non-empty string or number");
  }
  return value;
}

export function buildSubmitRequest(ctx) {
  const scope = ctx || {};
  const model = assertKnownModel(resolveModel(scope));
  const gateway = isGateway(scope);

  if (model === MODEL_INFO) {
    const userId = requireUserId(scope.requestBody);
    if (gateway) {
      return {
        url: upstreamBase(scope) + GATEWAY_VERIFY_PATH,
        method: "POST",
        headers: gatewayHeaders(scope, true),
        body: { user_id: userId },
      };
    }
    const url =
      upstreamBase(scope) +
      INFO_PATH +
      "?" +
      queryString({ uuid: requireApiKey(scope), user_id: userId });
    return { url: url, method: "GET", headers: jsonHeaders() };
  }

  const forwarded = otpParameters(scope.requestBody);
  if (gateway) {
    return {
      url: upstreamBase(scope) + GATEWAY_OTP_PATH,
      method: "POST",
      headers: gatewayHeaders(scope, true),
      body: forwarded,
    };
  }
  const params = { uuid: requireApiKey(scope) };
  const names = Object.keys(forwarded);
  for (let index = 0; index < names.length; index += 1) {
    params[names[index]] = forwarded[names[index]];
  }
  const url = upstreamBase(scope) + OTP_PATH + "?" + queryString(params);
  return { url: url, method: "GET", headers: jsonHeaders() };
}

export function parseSubmitResponse(ctx, response) {
  const status = httpStatus(response);
  const body = response ? response.body : null;
  const failure = upstreamError(body);
  if (failure) throw new Error(failure);
  if (status < 200 || status >= 300) {
    throw new Error("SimPass returned HTTP " + status);
  }

  const scope = ctx || {};
  const model = assertKnownModel(resolveModel(scope));

  if (isGateway(scope)) {
    // The upstream gateway already ran the vendor exchange and reports its own
    // task envelope, so its status -- not the raw vendor protocol -- decides
    // whether this task is already terminal.
    const object = asObject(body);
    const taskId = trimmed(object.task_id) || trimmed(object.id);
    if (!taskId) {
      throw new Error("the upstream New API gateway response did not include a task_id");
    }
    const result = object.result;
    const taskData =
      result && typeof result === "object" && !Array.isArray(result) ? result : object;
    const upstreamStatus = trimmed(object.status).toUpperCase();
    if (upstreamStatus === "SUCCESS") {
      return {
        taskId: taskId,
        taskData: taskData,
        immediate: { status: "SUCCESS", progress: trimmed(object.progress) || "100%" },
      };
    }
    if (upstreamStatus === "FAILURE") {
      return {
        taskId: taskId,
        taskData: taskData,
        immediate: {
          status: "FAILURE",
          reason: trimmed(object.fail_reason) || "the upstream gateway reported a failure",
        },
      };
    }
    return { taskId: taskId, taskData: taskData };
  }

  if (model === MODEL_INFO) {
    const object = asObject(body);
    if (!Number.isFinite(Number(object.level))) {
      throw new Error("SimPass user info response is missing a numeric level");
    }
    if (typeof object.risky !== "boolean") {
      throw new Error("SimPass user info response is missing a boolean risky flag");
    }
    // create_time and risk_details are display-only, so a missing value must not
    // fail a call the caller has already paid for.
    return {
      taskId: requirePublicTaskId(scope),
      taskData: object,
      immediate: { status: "SUCCESS", progress: "100%" },
    };
  }

  const object = asObject(body);
  const otpId = trimmed(object.otp_id);
  if (!otpId) throw new Error("SimPass response did not include otp_id");
  const expiresIn = Number(object.expires_in);
  return {
    taskId: otpId,
    taskData: {
      otp_id: otpId,
      expires_in: Number.isFinite(expiresIn) ? expiresIn : null,
      verify_url: upstreamBase(scope) + QR_PATH + "?otp_id=" + encodeURIComponent(otpId),
    },
  };
}

// --- polling -----------------------------------------------------------------

export function buildQueryRequest(ctx) {
  const scope = ctx || {};
  const model = assertKnownModel(resolveModel(scope));

  if (isGateway(scope)) {
    // Poll the upstream gateway's query route for its own public task id.
    const gatewayTaskId = trimmed(scope.taskId);
    if (!gatewayTaskId) throw new Error("SimPass task id is empty");
    return {
      url: upstreamBase(scope) + GATEWAY_TASK_PATH + encodeURIComponent(gatewayTaskId),
      method: "GET",
      headers: gatewayHeaders(scope, false),
    };
  }

  if (model === MODEL_INFO) {
    // Reached only if the host polls a task that already completed on submit.
    throw new Error("SimPass user info queries complete synchronously and have no task to retrieve");
  }
  const otpId = trimmed(scope.taskId);
  if (!otpId) throw new Error("SimPass OTP task id is empty");
  const url = upstreamBase(scope) + OTP_PATH + "?" + queryString({ otp_id: otpId });
  return { url: url, method: "GET", headers: jsonHeaders() };
}

export function parseTaskResult(ctx, body, response) {
  const scope = ctx || {};
  const model = resolveModel(scope);
  const status = pollStatus(response);
  const failure = upstreamError(body);

  if (isGateway(scope)) {
    // The upstream gateway already normalizes the vendor protocol, so its status
    // vocabulary is New API's own and maps across without translation.
    if (status === 404) {
      return {
        status: "FAILURE",
        reason: failure || "the upstream gateway no longer has this task",
      };
    }
    if (status === 401 || status === 403) {
      return {
        status: "FAILURE",
        reason: failure || "the upstream gateway rejected the channel token",
      };
    }
    if (status < 200 || status >= 300) {
      return {
        status: "UNKNOWN",
        reason: failure || "the upstream gateway returned HTTP " + status,
      };
    }
    const object = asObject(body);
    const upstreamStatus = trimmed(object.status).toUpperCase();
    const reason = trimmed(object.fail_reason) || failure;
    if (upstreamStatus === "SUCCESS") {
      return { status: "SUCCESS", progress: trimmed(object.progress) || "100%" };
    }
    if (upstreamStatus === "FAILURE") {
      return { status: "FAILURE", reason: reason || "the upstream gateway reported a failure" };
    }
    if (
      upstreamStatus === "QUEUED" ||
      upstreamStatus === "SUBMITTED" ||
      upstreamStatus === "NOT_START"
    ) {
      return { status: "QUEUED" };
    }
    if (upstreamStatus === "IN_PROGRESS") {
      return { status: "IN_PROGRESS" };
    }
    return {
      status: "UNKNOWN",
      reason: upstreamStatus
        ? 'unrecognized upstream gateway status "' + upstreamStatus + '"'
        : "the upstream gateway response is missing a status",
    };
  }

  if (model === MODEL_INFO) {
    return {
      status: "UNKNOWN",
      reason: "SimPass user info queries complete synchronously and have no asynchronous task",
    };
  }
  if (model !== MODEL_OTP) {
    return { status: "UNKNOWN", reason: 'SimPass does not serve model "' + model + '"' };
  }

  // An expired or unknown otp_id is terminal, not transient: never report it as
  // in progress or the task would keep occupying resources until the deadline.
  if (status === 404) {
    return { status: "FAILURE", reason: failure || "SimPass OTP is invalid or has expired" };
  }
  if (status === 401 || status === 403) {
    return { status: "FAILURE", reason: failure || "SimPass rejected the developer UUID" };
  }
  if (status < 200 || status >= 300) {
    return { status: "UNKNOWN", reason: failure || "SimPass returned HTTP " + status };
  }

  const otpStatus = trimmed(asObject(body).status).toLowerCase();
  if (!otpStatus) {
    return { status: "UNKNOWN", reason: "SimPass OTP response is missing a status field" };
  }
  // The polling endpoint only ever answers "not verified yet" or "verified": the
  // documented pending shape carries a status and nothing else, and a reply
  // without any status is treated as unrecognized above.
  if (otpStatus !== OTP_STATUS_VERIFIED) {
    return { status: "IN_PROGRESS" };
  }
  return { status: "SUCCESS", progress: "100%" };
}

// --- usage -------------------------------------------------------------------

export function extractUsage(ctx) {
  const scope = ctx || {};
  if (scope.usagePurpose === "billing_ratios") return null;
  return { requests: 1 };
}
