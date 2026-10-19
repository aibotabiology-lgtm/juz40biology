// BIO APP — Telegram арқылы кіру (Supabase Edge Function: tg-auth)
// Secrets: TG_CLIENT_ID, TG_CLIENT_SECRET (Edge Functions → Secrets)
const SB_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const ANON = Deno.env.get("SUPABASE_ANON_KEY")!;
const TG_ID = Deno.env.get("TG_CLIENT_ID")!;
const TG_SECRET = Deno.env.get("TG_CLIENT_SECRET")!;
const ALLOWED_REDIRECTS = ["https://biologyubt.netlify.app/"];

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (o: unknown, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { ...CORS, "Content-Type": "application/json" } });

const b64uDec = (s: string) => {
  const pad = (4 - (s.length % 4)) % 4;
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
const td = new TextDecoder();

async function verifyIdToken(tok: string) {
  const [h, p, sig] = tok.split(".");
  const header = JSON.parse(td.decode(b64uDec(h)));
  const payload = JSON.parse(td.decode(b64uDec(p)));
  if (header.alg !== "RS256") throw new Error("unsupported alg " + header.alg);
  const jwks = await (await fetch("https://oauth.telegram.org/.well-known/jwks.json")).json();
  const jwk = (jwks.keys || []).find((k: any) => !header.kid || k.kid === header.kid);
  if (!jwk) throw new Error("jwk not found");
  const key = await crypto.subtle.importKey(
    "jwk", { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"],
  );
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uDec(sig), new TextEncoder().encode(h + "." + p));
  if (!ok) throw new Error("bad signature");
  if (payload.iss !== "https://oauth.telegram.org") throw new Error("bad iss");
  const aud = (Array.isArray(payload.aud) ? payload.aud : [payload.aud]).map(String);
  if (!aud.includes(String(TG_ID))) throw new Error("bad aud");
  if (payload.exp * 1000 < Date.now()) throw new Error("expired");
  return payload;
}

const admin = (path: string, body: unknown) =>
  fetch(SB_URL + "/auth/v1/admin/" + path, {
    method: "POST",
    headers: { apikey: SERVICE, Authorization: "Bearer " + SERVICE, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "method" }, 405);
  try {
    const { code, code_verifier, redirect_uri } = await req.json();
    if (!code || !code_verifier || !ALLOWED_REDIRECTS.includes(redirect_uri)) return json({ error: "bad request" }, 400);

    // 1) code → id_token (Telegram OIDC)
    const tr = await fetch("https://oauth.telegram.org/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: "Basic " + btoa(TG_ID + ":" + TG_SECRET),
      },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri, code_verifier, client_id: TG_ID }),
    });
    const tok = await tr.json();
    if (!tok.id_token) return json({ error: "telegram: " + (tok.error_description || tok.error || tr.status) }, 401);
    const u = await verifyIdToken(tok.id_token);
    const tgId = String(u.id ?? u.sub);
    const prof = {
      name: u.name || [u.given_name, u.family_name].filter(Boolean).join(" ") || u.preferred_username || "Оқушы",
      username: u.preferred_username || "",
      photo: u.picture || "",
    };

    // 2) Supabase user (email is internal only, nothing is sent)
    const email = `tg${tgId}@biologyubt.netlify.app`;
    await admin("users", { email, email_confirm: true, user_metadata: { tg_id: tgId, ...prof } }); // 422 if exists — ok
    const gr = await admin("generate_link", { type: "magiclink", email });
    const gl = await gr.json();
    const hashed = gl.hashed_token || gl.properties?.hashed_token;
    if (!hashed) return json({ error: "link: " + JSON.stringify(gl).slice(0, 300) }, 500);

    // 3) session
    const vr = await fetch(SB_URL + "/auth/v1/verify", {
      method: "POST",
      headers: { apikey: ANON, "Content-Type": "application/json" },
      body: JSON.stringify({ type: "magiclink", token_hash: hashed }),
    });
    const sess = await vr.json();
    if (!sess.access_token) return json({ error: "verify: " + JSON.stringify(sess).slice(0, 300) }, 500);

    // 4) profile
    await fetch(SB_URL + "/rest/v1/profiles?on_conflict=id", {
      method: "POST",
      headers: {
        apikey: SERVICE, Authorization: "Bearer " + SERVICE, "Content-Type": "application/json",
        Prefer: "resolution=merge-duplicates,return=minimal",
      },
      body: JSON.stringify({ id: sess.user.id, tg_id: Number(tgId), ...prof, last_seen: new Date().toISOString() }),
    });

    return json({
      access_token: sess.access_token, refresh_token: sess.refresh_token, expires_in: sess.expires_in,
      user: { id: sess.user.id }, profile: prof,
    });
  } catch (e) {
    return json({ error: String((e as Error).message || e) }, 500);
  }
});
