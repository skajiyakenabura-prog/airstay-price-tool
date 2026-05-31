// POST /api/sheets-proxy
// Google Sheets API をサーバー側サービスアカウントで代理実行する
//
// 必要な環境変数（Cloudflare Pages > 設定 > 環境変数 > シークレット）:
//   GOOGLE_SA_EMAIL       - サービスアカウントのメールアドレス
//                           例: my-tool@my-project.iam.gserviceaccount.com
//   GOOGLE_SA_PRIVATE_KEY - サービスアカウントの秘密鍵（PEM形式）
//                           JSONキーファイルの "private_key" の値をそのまま貼り付け
//
// リクエスト body (JSON):
//   { "method": "GET"|"POST", "path": "spreadsheets/...", "body": { ... } }
//
// 認証: ツールのログイン JWT（Authorization: Bearer <token>）が必要

// ── JWT 検証ヘルパー（verify.js と同じロジック）──────────────────────────
function base64UrlToBytes(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
function base64UrlToJson(str) {
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(str)));
}
async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );
  const valid = await crypto.subtle.verify('HMAC', key, base64UrlToBytes(s), new TextEncoder().encode(`${h}.${p}`));
  if (!valid) return null;
  const payload = base64UrlToJson(p);
  if (payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

// ── サービスアカウント JWT + アクセストークン取得 ─────────────────────────
function base64url(data) {
  let binary;
  if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
    binary = String.fromCharCode(...new Uint8Array(data instanceof ArrayBuffer ? data : data.buffer));
  } else {
    binary = data;
  }
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function pemToArrayBuffer(pem) {
  // 環境変数に "\n" がエスケープされて入っている場合にも対応
  const normalized = pem.replace(/\\n/g, '\n');
  const b64 = normalized
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/\s/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function getGoogleAccessToken(saEmail, saPrivateKeyPem) {
  const now = Math.floor(Date.now() / 1000);
  const header  = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = base64url(JSON.stringify({
    iss: saEmail,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now,
  }));

  const keyData = pemToArrayBuffer(saPrivateKeyPem);
  const key = await crypto.subtle.importKey(
    'pkcs8', keyData,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', key,
    new TextEncoder().encode(`${header}.${payload}`)
  );
  const jwt = `${header}.${payload}.${base64url(sig)}`;

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok) throw new Error(tokenData.error_description || tokenData.error || 'アクセストークン取得失敗');
  return tokenData.access_token;
}

// ── CORS ヘッダー ──────────────────────────────────────────────────────────
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json',
};

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: corsHeaders });
}

export async function onRequestPost(context) {
  const { request, env } = context;

  // ── 1. ログイン済みか確認（一時的に無効化中）─────────────────────────
  // const auth = request.headers.get('Authorization') || '';
  // const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  // if (!token || !env.JWT_SECRET) {
  //   return new Response(JSON.stringify({ error: '認証が必要です' }), { status: 401, headers: corsHeaders });
  // }
  // const payload = await verifyJWT(token, env.JWT_SECRET);
  // if (!payload) {
  //   return new Response(JSON.stringify({ error: '認証トークンが無効です。再ログインしてください' }), { status: 401, headers: corsHeaders });
  // }

  // ── 2. サービスアカウント設定確認 ────────────────────────────────────
  const saEmail = env.GOOGLE_SA_EMAIL;
  const saKey   = env.GOOGLE_SA_PRIVATE_KEY;
  if (!saEmail || !saKey) {
    return new Response(JSON.stringify({ error: 'Google Sheets連携が設定されていません（管理者にお問い合わせください）' }), { status: 503, headers: corsHeaders });
  }

  // ── 3. リクエスト解析 ─────────────────────────────────────────────────
  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ error: 'リクエスト形式エラー' }), { status: 400, headers: corsHeaders });
  }
  const { method = 'GET', path, body: sheetsBody } = body;
  if (!path) {
    return new Response(JSON.stringify({ error: 'path が指定されていません' }), { status: 400, headers: corsHeaders });
  }

  // ── 4. Google アクセストークン取得 ───────────────────────────────────
  let accessToken;
  try {
    accessToken = await getGoogleAccessToken(saEmail, saKey);
  } catch (e) {
    return new Response(JSON.stringify({ error: 'Google認証エラー: ' + e.message }), { status: 502, headers: corsHeaders });
  }

  // ── 5. Sheets API へ転送 ─────────────────────────────────────────────
  const sheetsUrl = `https://sheets.googleapis.com/v4/${path}`;
  const fetchInit = {
    method,
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
  };
  if (method === 'POST' && sheetsBody !== undefined) {
    fetchInit.body = JSON.stringify(sheetsBody);
  }

  try {
    const sheetsRes = await fetch(sheetsUrl, fetchInit);
    const data = await sheetsRes.json();
    if (!sheetsRes.ok) {
      const msg = data?.error?.message || `HTTP ${sheetsRes.status}`;
      return new Response(JSON.stringify({ error: msg }), { status: sheetsRes.status, headers: corsHeaders });
    }
    return new Response(JSON.stringify(data), { status: 200, headers: corsHeaders });
  } catch (e) {
    return new Response(JSON.stringify({ error: 'Sheets APIエラー: ' + e.message }), { status: 502, headers: corsHeaders });
  }
}
