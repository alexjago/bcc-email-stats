type ParsedRecipient = {
  campaignId: string;
  token: string | null;
  signature: string | null;
};

type EventRow = {
  campaign_id: string;
  total: number;
  unique_recipients: number;
  first_received_at: number;
  last_received_at: number;
};

const encoder = new TextEncoder();
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: JSON_HEADERS });
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function base64UrlBytes(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4);
  try {
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return base64Url(new Uint8Array(digest));
}

function parseRecipient(address: string): ParsedRecipient | null {
  const localPart = address.trim().toLowerCase().split("@")[0];
  if (!localPart) return null;

  // Campaign IDs intentionally exclude hyphens so the first hyphen stays an
  // unambiguous separator; tokens may contain hyphens and end in `.signature`.
  const match = /^([a-z0-9_]{1,64})(?:-([a-z0-9][a-z0-9_-]{0,191})(?:\.([A-Za-z0-9_-]{16,128}))?)?$/.exec(localPart);
  if (!match) return null;

  return { campaignId: match[1], token: match[2] ?? null, signature: match[3] ?? null };
}

async function hasValidSignature(recipient: ParsedRecipient, secret: string): Promise<boolean> {
  if (!recipient.token || !recipient.signature) return false;
  const supplied = base64UrlBytes(recipient.signature);
  if (!supplied) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify("HMAC", key, arrayBuffer(supplied), encoder.encode(`${recipient.campaignId}:${recipient.token}`));
}

function bearerToken(request: Request): string | null {
  const authorization = request.headers.get("authorization");
  return authorization?.startsWith("Bearer ") ? authorization.slice(7) : null;
}

function readSecret(env: Env, name: "STATS_API_TOKEN" | "RECIPIENT_HMAC_SECRET"): string | undefined {
  const value = Reflect.get(env, name);
  return typeof value === "string" ? value : undefined;
}

async function authorised(request: Request, secret: string | undefined): Promise<boolean> {
  const supplied = bearerToken(request);
  if (!secret || !supplied) return false;
  const challenge = encoder.encode("bcc-email-stats API-token check");
  const expectedKey = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", expectedKey, challenge);
  const suppliedKey = await crypto.subtle.importKey("raw", encoder.encode(supplied), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  return crypto.subtle.verify("HMAC", suppliedKey, signature, challenge);
}

async function handleStats(request: Request, env: Env, pathname: string): Promise<Response> {
  if (!(await authorised(request, readSecret(env, "STATS_API_TOKEN")))) return json({ error: "unauthorised" }, 401);

  const campaignMatch = /^\/api\/campaigns\/([a-z0-9_]{1,64})$/.exec(pathname);
  if (campaignMatch) {
    const row = await env.DB.prepare(
      `SELECT campaign_id,
              COUNT(*) AS total,
              COUNT(DISTINCT token_fingerprint) AS unique_recipients,
              MIN(received_at) AS first_received_at,
              MAX(received_at) AS last_received_at
       FROM email_events WHERE campaign_id = ?`,
    ).bind(campaignMatch[1]).first<EventRow>();
    return json(row ?? { campaign_id: campaignMatch[1], total: 0, unique_recipients: 0, first_received_at: null, last_received_at: null });
  }

  if (pathname === "/api/campaigns") {
    const result = await env.DB.prepare(
      `SELECT campaign_id,
              COUNT(*) AS total,
              COUNT(DISTINCT token_fingerprint) AS unique_recipients,
              MIN(received_at) AS first_received_at,
              MAX(received_at) AS last_received_at
       FROM email_events GROUP BY campaign_id ORDER BY last_received_at DESC`,
    ).all<EventRow>();
    return json({ campaigns: result.results });
  }

  return json({ error: "not_found" }, 404);
}

export default {
  async email(message, env): Promise<void> {
    const recipient = parseRecipient(message.to);
    const signatureRequired = String(env.REQUIRE_RECIPIENT_SIGNATURE) === "true";
    const hmacSecret = readSecret(env, "RECIPIENT_HMAC_SECRET");
    const signedCorrectly = hmacSecret
      ? await hasValidSignature(recipient ?? { campaignId: "", token: null, signature: null }, hmacSecret)
      : false;

    if (!recipient || (signatureRequired && !signedCorrectly)) {
      message.setReject("Unrecognised campaign address");
      return;
    }

    const messageId = message.headers.get("message-id");
    const dedupeKey = await sha256(`${message.to}\n${messageId ?? crypto.randomUUID()}`);
    const tokenFingerprint = recipient.token ? await sha256(recipient.token) : null;

    await env.DB.prepare(
      "INSERT OR IGNORE INTO email_events (dedupe_key, campaign_id, token_fingerprint, received_at) VALUES (?, ?, ?, ?)",
    ).bind(dedupeKey, recipient.campaignId, tokenFingerprint, Date.now()).run();

    console.log(JSON.stringify({ event: "email_counted", campaignId: recipient.campaignId, hasToken: recipient.token !== null }));
  },

  async fetch(request, env): Promise<Response> {
    if (request.method !== "GET") return json({ error: "method_not_allowed" }, 405);
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith("/api/")) return await handleStats(request, env, url.pathname);
      return json({ service: "bcc-email-stats", endpoints: ["GET /api/campaigns", "GET /api/campaigns/:campaignId"] });
    } catch (error) {
      console.error(JSON.stringify({ event: "request_failed", message: error instanceof Error ? error.message : "unknown" }));
      return json({ error: "internal_error" }, 500);
    }
  },
} satisfies ExportedHandler<Env>;
