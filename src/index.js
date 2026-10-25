const MAX_BODY_BYTES = 8192;
const ALLOWED_RULES = {
  SECRET_KEY: { title: "코드 안의 API 키나 비밀번호 후보", level: "높음" },
  SQL_INJECTION: { title: "입력값이 데이터베이스 명령에 섞일 가능성", level: "높음" },
  DANGEROUS_EVAL: { title: "입력값이 프로그램 코드로 실행될 가능성", level: "높음" },
  XSS_SINK: { title: "입력값이 웹페이지 코드에 들어갈 가능성", level: "중간" },
  CORS_WILDCARD: { title: "모든 사이트 요청을 허용할 가능성", level: "중간" },
  DEBUG_MODE: { title: "운영 화면에 오류 정보가 보일 가능성", level: "중간" },
  WEAK_HASH: { title: "오래된 암호화 방식 사용 후보", level: "중간" },
  SHELL_EXEC: { title: "입력값이 컴퓨터 명령에 들어갈 가능성", level: "중간" },
  INSECURE_HTTP: { title: "암호화되지 않은 HTTP 주소 사용 후보", level: "낮음" },
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

async function readLimitedBody(request) {
  const length = Number(request.headers.get("content-length") || 0);
  if (length > MAX_BODY_BYTES) throw new Error("요청 크기가 너무 커요.");
  if (!request.body) throw new Error("요청 내용을 읽지 못했어요.");

  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new Error("요청 크기가 너무 커요.");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

async function handleAiReview(request, env) {
  if (request.method !== "POST") return json({ error: "POST 요청만 사용할 수 있어요." }, 405);

  const url = new URL(request.url);
  const origin = request.headers.get("origin");
  if (!origin || origin !== url.origin) return json({ error: "같은 사이트에서 보낸 요청만 사용할 수 있어요." }, 403);
  if (!env.GEMINI_API_KEY) return json({ error: "Gemini 키가 연결되지 않았어요. Cloudflare의 Worker secret 설정을 확인해 주세요." }, 503);
  if (!env.AI_LIMITER) return json({ error: "요청 제한 설정을 찾지 못했어요. Cloudflare 설정을 확인해 주세요." }, 503);

  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const limit = await env.AI_LIMITER.limit({ key: ip });
  if (!limit.success) return json({ error: "요약 요청이 잠시 많아요. 1분 뒤에 다시 시도해 주세요." }, 429);

  let body;
  try {
    body = JSON.parse(await readLimitedBody(request));
  } catch (error) {
    return json({ error: error.message || "요청 형식이 올바르지 않아요." }, 400);
  }
  if (!Array.isArray(body.issues) || body.issues.length === 0) {
    return json({ error: "요약할 점검 항목이 없어요." }, 400);
  }
  if (body.issues.length > 30) return json({ error: "한 번에 최대 30개 항목까지 요약할 수 있어요." }, 400);

  // Only send known rule labels and levels. File names, source code, and user text stay in the browser.
  const findings = body.issues
    .filter((item) => item && typeof item.rule === "string" && ALLOWED_RULES[item.rule])
    .map((item) => ALLOWED_RULES[item.rule]);
  if (!findings.length) return json({ error: "요약할 수 있는 점검 항목이 없어요." }, 400);

  const prompt = [
    "한국어로만 답하고, 아래 요구에 맞는 JSON 객체만 작성하세요.",
    "필드는 summary(쉬운 한눈 요약 문자열), priorityActions(먼저 확인할 일 최대 3개의 문자열 배열), repairPrompt(바이브코딩 도구에 붙여넣을 수정 요청문 문자열)입니다.",
    "목록은 규칙 기반 예비 점검의 확인 후보입니다. 실제 취약점으로 확정하거나 서비스가 안전하다고 단정하지 마세요.",
    "초보자도 이해할 짧고 쉬운 말로 쓰세요. 위험한 전문용어는 풀어서 설명하세요.",
    "코드와 파일은 전달되지 않았습니다. 파일명, 줄 번호, 실제 문제 위치를 만들지 마세요.",
    "수정 요청문에는 주변 코드를 확인하고 실제 문제일 때만 기존 기능을 유지하며 고치고, 잘못된 경고면 이유를 설명하고 수정하지 말라고 적으세요. 확인하지 않은 항목을 해결됐다고 주장하지 말라고 하세요.",
    "발견 후보 목록:",
    ...findings.map((item) => `- ${item.level}: ${item.title}`),
  ].join("\n");

  let upstream;
  try {
    upstream = await fetch("https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-goog-api-key": env.GEMINI_API_KEY,
      },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { responseMimeType: "application/json", thinkingConfig: { thinkingLevel: "low" } },
      }),
    });
  } catch {
    return json({ error: "Gemini에 연결하지 못했어요. 잠시 뒤 다시 시도해 주세요." }, 502);
  }
  if (!upstream.ok) {
    const hints = {
      400: "요청 형식, 키 종류, 또는 모델 접근 권한을 확인해 주세요.",
      401: "GEMINI_API_KEY가 올바른지 확인해 주세요.",
      403: "이 키의 Gemini API 사용 권한과 결제 설정을 확인해 주세요.",
      404: "요청한 Gemini 모델을 찾지 못했어요. 모델 설정을 확인해 주세요.",
      429: "Gemini 사용량 한도에 도달했어요. 사용량·결제 한도를 확인해 주세요.",
    };
    const upstreamError = await upstream.clone().json().catch(() => null);
    const detail = String(upstreamError?.error?.message || "")
      .replace(/AIza[0-9A-Za-z_-]{20,}/g, "[키 숨김]")
      .replace(/AQ\.[A-Za-z0-9._-]{12,}/g, "[키 숨김]")
      .replace(/\s+/g, " ")
      .slice(0, 220);
    console.warn("Gemini API request failed", { status: upstream.status, detail });
    const locationBlocked = /user location is not supported/i.test(detail);
    const hint = locationBlocked
      ? "Gemini가 Cloudflare 요청 위치를 허용하지 않았어요. Worker를 한국 인근에서 실행하도록 설정했어요. 계속되면 Google이 Cloudflare IP 위치를 다르게 판단하는 문제일 수 있어요."
      : hints[upstream.status] || "잠시 뒤 다시 시도하거나 Gemini 설정을 확인해 주세요.";
    const detailText = detail ? ` Gemini 안내: ${detail}` : "";
    return json({ error: `Gemini 요청 실패 (HTTP ${upstream.status}). ${hint}${detailText}` }, 502);
  }

  let result;
  try {
    result = await upstream.json();
  } catch {
    return json({ error: "Gemini 답변을 읽지 못했어요. 다시 시도해 주세요." }, 502);
  }
  const candidate = result.candidates?.[0];
  if (candidate?.finishReason === "MAX_TOKENS") {
    return json({ error: "Gemini 답변이 중간에 끊겼어요. 다시 눌러 주세요." }, 502);
  }
  const rawText = candidate?.content?.parts
    ?.filter((part) => !part.thought)
    .map((part) => part.text || "")
    .join("\n")
    .trim();
  if (!rawText) return json({ error: "Gemini가 분석을 만들지 못했어요. 다시 시도해 주세요." }, 502);

  let analysis;
  try {
    analysis = JSON.parse(rawText);
  } catch {
    return json({ error: "Gemini 답변 형식을 읽지 못했어요. 다시 시도해 주세요." }, 502);
  }
  const summary = typeof analysis.summary === "string" ? analysis.summary.trim().slice(0, 600) : "";
  const priorityActions = Array.isArray(analysis.priorityActions)
    ? analysis.priorityActions.filter((item) => typeof item === "string").slice(0, 3).map((item) => item.slice(0, 240))
    : [];
  const repairPrompt = typeof analysis.repairPrompt === "string" ? analysis.repairPrompt.trim().slice(0, 3000) : "";
  if (!summary || !priorityActions.length || !repairPrompt) {
    return json({ error: "Gemini 답변에 필요한 내용이 빠졌어요. 다시 시도해 주세요." }, 502);
  }
  return json({ analysis: { summary, priorityActions, repairPrompt } });
}


async function handleUsage(request, env) {
  if (!env.USAGE_COUNTER) return json({ error: "사용자 집계를 준비하지 못했어요." }, 503);
  if (request.method !== "GET" && request.method !== "POST") {
    return json({ error: "GET 또는 POST 요청만 사용할 수 있어요." }, 405);
  }
  if (request.method === "POST") {
    const url = new URL(request.url);
    const origin = request.headers.get("origin");
    if (!origin || origin !== url.origin) return json({ error: "같은 사이트에서 보낸 요청만 사용할 수 있어요." }, 403);
    let body;
    try {
      body = JSON.parse(await readLimitedBody(request));
    } catch {
      return json({ error: "집계 요청을 읽지 못했어요." }, 400);
    }
    if (typeof body.visitorId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(body.visitorId)) {
      return json({ error: "브라우저 식별값이 올바르지 않아요." }, 400);
    }
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body.visitorId));
    const hashedId = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    const id = env.USAGE_COUNTER.idFromName("completed-scan-visitors");
    const stub = env.USAGE_COUNTER.get(id);
    const response = await stub.fetch("https://usage-counter/complete", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ visitorId: hashedId }),
    });
    return new Response(response.body, { status: response.status, headers: response.headers });
  }
  const id = env.USAGE_COUNTER.idFromName("completed-scan-visitors");
  return env.USAGE_COUNTER.get(id).fetch("https://usage-counter/count");
}

export class UsageCounter {
  constructor(ctx) {
    this.ctx = ctx;
    ctx.blockConcurrencyWhile(async () => {
      ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS completed_visitors (visitor_id TEXT PRIMARY KEY)");
    });
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/complete") {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "집계 요청이 올바르지 않아요." }, 400);
      }
      if (typeof body.visitorId !== "string" || !/^[0-9a-f]{64}$/.test(body.visitorId)) {
        return json({ error: "집계 식별값이 올바르지 않아요." }, 400);
      }
      this.ctx.storage.sql.exec("INSERT OR IGNORE INTO completed_visitors (visitor_id) VALUES (?)", body.visitorId);
    } else if (request.method !== "GET" || url.pathname !== "/count") {
      return json({ error: "요청 경로를 찾을 수 없어요." }, 404);
    }
    const row = this.ctx.storage.sql.exec("SELECT COUNT(*) AS count FROM completed_visitors").one();
    return json({ count: Number(row.count) });
  }
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/ai-review") return handleAiReview(request, env);\n    if (url.pathname === "/api/usage") return handleUsage(request, env);
    return env.ASSETS.fetch(request);
  },
};
