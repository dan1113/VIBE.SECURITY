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
    "한국어로 답하세요. 이 목록은 규칙 기반 예비 점검에서 발견한 확인 후보입니다.",
    "실제 취약점으로 확정하거나 서비스가 안전하다고 단정하지 마세요.",
    "개발 초보자에게 쉬운 말로, 150자 안팎으로 설명하세요.",
    "전체적으로 무엇을 먼저 확인하면 좋을지와 첫 행동을 알려주세요.",
    "코드나 파일은 전달되지 않았으므로 실제 문제 위치를 추측하지 마세요.",
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
        generationConfig: { maxOutputTokens: 700, thinkingConfig: { thinkingLevel: "low" } },
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
    const hint = hints[upstream.status] || "잠시 뒤 다시 시도하거나 Gemini 설정을 확인해 주세요.";
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
  const summary = candidate?.content?.parts
    ?.filter((part) => !part.thought)
    .map((part) => part.text || "")
    .join("\n")
    .trim();
  if (!summary) return json({ error: "Gemini가 요약을 만들지 못했어요. 다시 시도해 주세요." }, 502);
  return json({ summary: summary.slice(0, 3000) });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/ai-review") return handleAiReview(request, env);
    return env.ASSETS.fetch(request);
  },
};
