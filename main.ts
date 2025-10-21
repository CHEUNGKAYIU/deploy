/**
 * OpenAI 兼容 API 服务 - Deno 版本
 * 提供标准的 /v1/chat/completions 接口，桥接到 CTO.NEW AI 服务。
 *
 * 部署方式:
 * - Deno Deploy: deno deploy --project=<project-name> main.ts
 * - 本地调试: deno run --allow-net --allow-env main.ts
 */
​
// ========== 类型定义 ==========
interface Message {
  role: string;
  content: string;
}
​
interface ChatCompletionRequest {
  model: string;
  messages: Message[];
  stream?: boolean;
  temperature?: number;
  top_p?: number;
  max_tokens?: number;
}
​
interface ChatCompletionResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: Message;
    finish_reason: string;
  }>;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}
​
type NormalizedMessage = Pick<Message, "role" | "content">;
​
interface ConversationState {
  chatId: string;
  adapter: string;
  lastUpdated: number;
}
​
// ========== 配置 ==========
const MODEL_MAPPING: Record<string, string> = {
  "gpt-5": "GPT5",
  "claude-sonnet-4-5": "ClaudeSonnet4_5",
};
​
const DEFAULT_ADAPTER = "ClaudeSonnet4_5";
const CONVERSATION_TTL_MS = 1000 * 60 * 60; // 1 小时缓存
​
// ========== 会话缓存 ==========
const conversationStore = new Map<string, ConversationState>();
​
function cleanupConversationStore(now: number = Date.now()) {
  for (const [key, state] of conversationStore) {
    if (now - state.lastUpdated > CONVERSATION_TTL_MS) {
      conversationStore.delete(key);
    }
  }
}
​
function normalizeMessages(messages: Message[]): NormalizedMessage[] {
  return messages
    .filter((msg) => typeof msg?.role === "string" && typeof msg?.content === "string")
    .map((msg) => ({
      role: msg.role,
      content: msg.content,
    }));
}
​
function createHistoryKey(messages: NormalizedMessage[]): string {
  return JSON.stringify(messages);
}
​
// ========== 环境变量工具 ==========
function safeGetEnv(key: string): string | undefined {
  const maybeDeno = (globalThis as { Deno?: { env?: { get?: (k: string) => string | undefined } } }).Deno;
  const envGetter = maybeDeno?.env?.get;
  if (typeof envGetter !== "function") {
    return undefined;
  }
  try {
    return envGetter(key) ?? undefined;
  } catch {
    return undefined;
  }
}
​
function resolveCookiesFromEnv(): string | undefined {
  return safeGetEnv("COOKIES")?.trim() || undefined;
}
​
function extractCookieFromRequest(request: Request): string | undefined {
  const authorization = request.headers.get("authorization") ?? request.headers.get("Authorization");
  let token: string | undefined;
​
  if (authorization) {
    const match = authorization.match(/^Bearer\s+(.+)$/i);
    if (match?.[1]) {
      token = match[1].trim();
    }
  }
​
  if (!token) {
    token = request.headers.get("x-api-key") ?? request.headers.get("X-API-Key") ?? undefined;
    token = token?.trim();
  }
​
  if (!token) return undefined;
​
  const lower = token.toLowerCase();
  if (lower.startsWith("base64:") || lower.startsWith("b64:")) {
    const encoded = token.substring(token.indexOf(":") + 1);
    try {
      token = atob(encoded.trim());
    } catch {
      // 如果解码失败则继续使用原始 token
    }
  }
​
  return token;
}
​
// ========== Cookie 池 ==========
class CookiePool {
  private cookies: string[] = [];
  private currentIndex = 0;
​
  constructor(cookieString: string) {
    this.loadCookies(cookieString);
  }
​
  private loadCookies(cookieString: string) {
    this.cookies = cookieString
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"));
​
    if (this.cookies.length === 0) {
      throw new Error("未找到有效的 Cookie");
    }
  }
​
  getNextCookie(): string {
    const cookie = this.cookies[this.currentIndex];
    this.currentIndex = (this.currentIndex + 1) % this.cookies.length;
    return cookie;
  }
}
​
// ========== 核心请求函数 ==========
async function getClerkInfo(cookie: string): Promise<{ sessionId: string; wsUserToken: string }> {
  const url = new URL("https://clerk.cto.new/v1/me/organization_memberships");
  url.searchParams.set("paginated", "true");
  url.searchParams.set("limit", "10");
  url.searchParams.set("offset", "0");
  url.searchParams.set("__clerk_api_version", "2025-04-10");
  url.searchParams.set("_clerk_js_version", "5.102.0");
​
  const response = await fetch(url.toString(), {
    headers: {
      accept: "application/json",
      cookie,
      "user-agent": "Mozilla/5.0",
    },
  });
​
  if (response.status === 401) {
    throw new Error("凭证校验失败 (401)，请确认 Cookie 是否仍然有效，并包含 __client、__session 等必要字段");
  }
​
  if (!response.ok) {
    throw new Error(`获取 Clerk 信息失败: ${response.status}`);
  }
​
  const data = await response.json();
  const sessionId = data.client?.last_active_session_id;
  const wsUserToken = data.client?.sessions?.[0]?.user?.id;
​
  if (!sessionId || !wsUserToken) {
    throw new Error("Clerk 返回数据不完整，无法获取 sessionId 或 wsUserToken");
  }
​
  return { sessionId, wsUserToken };
}
​
async function getJwtFromClerk(sessionId: string, cookie: string): Promise<string> {
  const url = `https://clerk.cto.new/v1/client/sessions/${sessionId}/tokens?__clerk_api_version=2025-04-10&_clerk_js_version=5.101.1`;
​
  const response = await fetch(url, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
      cookie,
      "user-agent": "Mozilla/5.0",
    },
  });
​
  if (!response.ok) {
    throw new Error(`获取 JWT 失败: ${response.status}`);
  }
​
  const data = await response.json();
  if (!data.jwt) {
    throw new Error("JWT 返回为空");
  }
​
  return data.jwt;
}
​
async function sendChatMessage(jwt: string, prompt: string, adapter: string, existingChatId?: string): Promise<string> {
  const chatId = existingChatId ?? crypto.randomUUID();
  const url = "https://api.enginelabs.ai/engine-agent/chat";
​
  const response = await fetch(url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${jwt}`,
      accept: "application/json",
      "content-type": "application/json",
      origin: "https://cto.new",
      referer: "https://cto.new",
    },
    body: JSON.stringify({
      prompt,
      chatHistoryId: chatId,
      adapterName: adapter,
    }),
  });
​
  if (!response.ok) {
    throw new Error(`发送对话失败: ${response.status}`);
  }
​
  return chatId;
}
​
async function getAiResponse(chatId: string, wsUserToken: string): Promise<string> {
  const wsUrl = `wss://api.enginelabs.ai/engine-agent/chat-histories/${chatId}/buffer/stream?token=${wsUserToken}`;
  const ws = new WebSocket(wsUrl);
  let buffer = "";
​
  return new Promise((resolve, reject) => {
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "update" && data.buffer) {
          try {
            const inner = JSON.parse(data.buffer);
            if (inner.type === "chat" && inner.chat?.content) {
              buffer += inner.chat.content;
            }
          } catch {
            // 忽略内部解析错误
          }
        } else if (data.type === "state" && !data.state?.inProgress) {
          ws.close();
          resolve(buffer.trim());
        }
      } catch {
        // 忽略解析错误
      }
    };
​
    ws.onerror = () => {
      reject(new Error("WebSocket 发生错误"));
    };
​
    ws.onclose = () => {
      if (buffer) {
        resolve(buffer.trim());
      } else {
        reject(new Error("WebSocket 提前关闭且未返回内容"));
      }
    };
  });
}
​
async function* streamAiResponse(chatId: string, wsUserToken: string): AsyncGenerator<string> {
  const wsUrl = `wss://api.enginelabs.ai/engine-agent/chat-histories/${chatId}/buffer/stream?token=${wsUserToken}`;
  const ws = new WebSocket(wsUrl);
  const queue: string[] = [];
  let done = false;
  let error: Error | null = null;
​
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
​
      if (data.type === "update" && data.buffer) {
        try {
          const inner = JSON.parse(data.buffer);
          if (inner.type === "chat" && inner.chat?.content) {
            const chunk = {
              id: `chatcmpl-${chatId}`,
              object: "chat.completion.chunk",
              created: Math.floor(Date.now() / 1000),
              model: "gpt-4",
              choices: [
                {
                  index: 0,
                  delta: { content: inner.chat.content },
                  finish_reason: null,
                },
              ],
            };
            queue.push(`data: ${JSON.stringify(chunk)}\n\n`);
          }
        } catch {
          // 忽略内部解析错误
        }
      } else if (data.type === "state" && !data.state?.inProgress) {
        const finalChunk = {
          id: `chatcmpl-${chatId}`,
          object: "chat.completion.chunk",
          created: Math.floor(Date.now() / 1000),
          model: "gpt-4",
          choices: [
            {
              index: 0,
              delta: {},
              finish_reason: "stop",
            },
          ],
        };
        queue.push(`data: ${JSON.stringify(finalChunk)}\n\n`);
        queue.push("data: [DONE]\n\n");
        done = true;
        ws.close();
      }
    } catch {
      // 忽略解析错误
    }
  };
​
  ws.onerror = () => {
    error = new Error("WebSocket 发生错误");
    done = true;
  };
​
  ws.onclose = () => {
    done = true;
  };
​
  while (!done || queue.length > 0) {
    if (error) throw error;
    if (queue.length > 0) {
      yield queue.shift()!;
    } else {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
}
​
function estimateTokens(text: string): number {
  return Math.floor(text.length / 4);
}
​
function buildChatCompletionResponse(chatId: string, model: string, prompt: string, completion: string): ChatCompletionResponse {
  return {
    id: `chatcmpl-${chatId}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        index: 0,
        message: { role: "assistant", content: completion },
        finish_reason: "stop",
      },
    ],
    usage: {
      prompt_tokens: estimateTokens(prompt),
      completion_tokens: estimateTokens(completion),
      total_tokens: estimateTokens(prompt) + estimateTokens(completion),
    },
  };
}
​
async function handleChatCompletion(
  request: ChatCompletionRequest,
  cookiePool: CookiePool | null,
  overrideCookie?: string,
): Promise<Response> {
  cleanupConversationStore();
​
  const normalizedMessages = normalizeMessages(request.messages);
  const lastUserIndex = normalizedMessages.map((msg, idx) => (msg.role === "user" ? idx : -1)).filter((idx) => idx >= 0).pop() ?? -1;
​
  if (lastUserIndex === -1) {
    return new Response(JSON.stringify({ error: "缺少用户消息，无法生成回复" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }
​
  const userMessage = normalizedMessages[lastUserIndex];
  const historyBeforeUser = normalizedMessages.slice(0, lastUserIndex);
  const historyKey = createHistoryKey(historyBeforeUser);
​
  const adapter = MODEL_MAPPING[request.model] ?? DEFAULT_ADAPTER;
  const existingState = conversationStore.get(historyKey);
  const existingChatId = existingState && existingState.adapter === adapter ? existingState.chatId : undefined;
​
  const cookie = overrideCookie?.trim() || cookiePool?.getNextCookie();
  if (!cookie) {
    return new Response(JSON.stringify({ error: "缺少 Cookie，请通过 Authorization 或 X-API-Key 提供，或在服务器环境变量中设置 COOKIES" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }
​
  const { sessionId, wsUserToken } = await getClerkInfo(cookie);
  const jwt = await getJwtFromClerk(sessionId, cookie);
  const chatId = await sendChatMessage(jwt, userMessage.content, adapter, existingChatId);
​
  const registerConversation = (assistantContent: string) => {
    const historyWithAssistant = normalizedMessages.slice(0, lastUserIndex + 1).concat({
      role: "assistant",
      content: assistantContent,
    });
    const nextKey = createHistoryKey(historyWithAssistant);
    conversationStore.set(nextKey, {
      chatId,
      adapter,
      lastUpdated: Date.now(),
    });
  };
​
  if (request.stream) {
    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      async start(controller) {
        let assembled = "";
        try {
          for await (const chunk of streamAiResponse(chatId, wsUserToken)) {
            if (chunk.startsWith("data: ")) {
              const payload = chunk.slice(6).trim();
              if (payload && payload !== "[DONE]") {
                try {
                  const parsed = JSON.parse(payload);
                  const delta = parsed?.choices?.[0]?.delta?.content ?? "";
                  if (delta) {
                    assembled += delta;
                  }
                } catch {
                  // 忽略解析错误
                }
              }
            }
            controller.enqueue(encoder.encode(chunk));
          }
          registerConversation(assembled.trim());
          controller.close();
        } catch (error) {
          controller.error(error);
        }
      },
    });
​
    return withCorsHeaders(new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
      },
    }));
  }
​
  const completion = await getAiResponse(chatId, wsUserToken);
  registerConversation(completion);
​
  return new Response(JSON.stringify(buildChatCompletionResponse(chatId, request.model, userMessage.content, completion)), {
    headers: { "Content-Type": "application/json" },
  });
}
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
"Access-Control-Allow-Headers": "*", // ✅ 允许所有自定义请求头
  "Access-Control-Max-Age": "86400",
};
function withCorsHeaders(resp: Response): Response {
  const newHeaders = new Headers(resp.headers);
  for (const [k, v] of Object.entries(CORS_HEADERS)) {
    newHeaders.set(k, v);
  }
  return new Response(resp.body, {
    status: resp.status,
    headers: newHeaders,
  });
}
async function handleRequest(request: Request, cookiePool: CookiePool | null): Promise<Response> {
  const url = new URL(request.url);
​
  if (request.method === "OPTIONS") {
    return withCorsHeaders(new Response(null, { status: 204 }));
  }
​
  if (url.pathname === "/" && request.method === "GET") {
    return withCorsHeaders(new Response(
      JSON.stringify({
        message: "OpenAI Compatible API Server",
        endpoints: {
          chat: "/v1/chat/completions",
          models: "/v1/models",
        },
      }),
      { headers: {"Content-Type": "application/json" } },
    ));
  }
​
  if (url.pathname === "/v1/models" && request.method === "GET") {
    const models = Object.keys(MODEL_MAPPING).map((modelName) => ({
      id: modelName,
      object: "model",
      created: Math.floor(Date.now() / 1000),
      owned_by: "cto-new",
    }));
​
    return withCorsHeaders(new Response(
      JSON.stringify({ object: "list", data: models }),
      { headers: {"Content-Type": "application/json" } },
    ));
  }
​
  if (url.pathname === "/v1/chat/completions" && request.method === "POST") {
    const overrideCookie = extractCookieFromRequest(request);
    const body = (await request.json()) as ChatCompletionRequest;
    return handleChatCompletion(body, cookiePool, overrideCookie);
  }
​
  return withCorsHeaders(new Response("Not Found", { status: 404 }));
}
​
// ========== Deno 入口 ==========
const baseCookies = resolveCookiesFromEnv();
const sharedCookiePool = baseCookies ? new CookiePool(baseCookies) : null;
​
const handler = async (request: Request): Promise<Response> => {
  try {
    return await handleRequest(request, sharedCookiePool);
  } catch (error) {
    return new Response(
      JSON.stringify({ error: error instanceof Error ? error.message : "Server error" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }
};
​
if (typeof Deno !== "undefined" && typeof Deno.serve === "function") {
  const portValue = safeGetEnv("PORT");
  if (portValue) {
    const port = Number(portValue);
    if (Number.isFinite(port) && port > 0) {
      console.log(`本地 Deno 服务启动，监听端口 ${port}`);
      Deno.serve({ port }, handler);
    } else {
      console.warn(`检测到非法端口 ${portValue}，回退为自动端口配置`);
      Deno.serve(handler);
    }
  } else {
    Deno.serve(handler);
  }
} else {
  throw new Error("当前运行环境不支持 Deno.serve");
}
