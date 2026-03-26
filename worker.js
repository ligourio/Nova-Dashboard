// ═══════════════════════════════════════════════════════════
//  NOVA DASHBOARD — CLOUDFLARE WORKER
//
//  Secrets needed in Cloudflare (Settings → Variables → Encrypt):
//       ANTHROPIC_KEY        → Anthropic API key
//       SUPABASE_URL         → Supabase project URL
//       SUPABASE_KEY         → Supabase service_role key
//       PASSWORD_HASH        → generated via /hash endpoint
//       GOOGLE_CLIENT_SECRET → Google OAuth client secret
//       TAVILY_KEY           → Tavily search API key (tvly-...)
// ═══════════════════════════════════════════════════════════

const ALLOWED_ORIGIN = "https://ligourio.github.io";
const GOOGLE_CLIENT_ID = "1038373995495-e4cb55rt5ijtg5c2pu8e9q23gor6ahru.apps.googleusercontent.com";
const SESSION_DAYS    = 7;
const RATE_LIMIT_MAX  = 5;
const RATE_LIMIT_MINS = 15;
const WORKER_URL      = "https://nova-proxy.dkaloudis07.workers.dev";
const GOOGLE_SCOPES   = "https://www.googleapis.com/auth/calendar";

const corsHeaders = (origin) => ({
  "Access-Control-Allow-Origin": origin === ALLOWED_ORIGIN ? ALLOWED_ORIGIN : "",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Session-Token",
  "Access-Control-Max-Age": "86400",
});

function jsonResponse(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(origin) },
  });
}

async function hashPassword(password, salt) {
  const encoder = new TextEncoder();
  const data = encoder.encode(salt + password + salt);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

function generateToken(length = 64) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function supabase(env, method, path, body = null) {
  const res = await fetch(`${env.SUPABASE_URL}/rest/v1/${path}`, {
    method,
    headers: {
      "apikey": env.SUPABASE_KEY,
      "Authorization": `Bearer ${env.SUPABASE_KEY}`,
      "Content-Type": "application/json",
      "Prefer": method === "POST" ? "return=representation" : "",
    },
    body: body ? JSON.stringify(body) : null,
  });
  if (!res.ok && res.status !== 404) {
    const err = await res.text();
    throw new Error(`Supabase error ${res.status}: ${err}`);
  }
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

async function checkRateLimit(env, ip) {
  const windowStart = new Date(Date.now() - RATE_LIMIT_MINS * 60 * 1000).toISOString();
  const rows = await supabase(env, "GET",
    `login_attempts?ip=eq.${encodeURIComponent(ip)}&created_at=gte.${windowStart}&select=id`
  );
  return (rows || []).length;
}

async function recordAttempt(env, ip, success) {
  await supabase(env, "POST", "login_attempts", {
    ip, success, created_at: new Date().toISOString(),
  });
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  await supabase(env, "DELETE", `login_attempts?created_at=lt.${cutoff}`).catch(() => {});
}

async function validateSession(env, token) {
  if (!token || token.length < 64) return false;
  const rows = await supabase(env, "GET",
    `sessions?token=eq.${encodeURIComponent(token)}&select=expires_at`
  );
  if (!rows || rows.length === 0) return false;
  return new Date(rows[0].expires_at) > new Date();
}

async function getGoogleTokens(env) {
  const rows = await supabase(env, "GET", "google_tokens?id=eq.1&select=*").catch(() => null);
  return rows?.[0] || null;
}

async function saveGoogleTokens(env, accessToken, refreshToken, expiresAt) {
  await supabase(env, "POST", "google_tokens", {
    id: 1,
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_at: expiresAt,
    updated_at: new Date().toISOString(),
  }).catch(async () => {
    await supabase(env, "PATCH", "google_tokens?id=eq.1", {
      access_token: accessToken,
      ...(refreshToken ? { refresh_token: refreshToken } : {}),
      expires_at: expiresAt,
      updated_at: new Date().toISOString(),
    });
  });
}

async function refreshGoogleToken(env, refreshToken) {
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: refreshToken,
      grant_type: "refresh_token",
    }),
  });
  const data = await res.json();
  if (data.error) throw new Error(data.error);
  return data;
}

async function getValidAccessToken(env) {
  const tokens = await getGoogleTokens(env);
  if (!tokens) return null;
  if (new Date(tokens.expires_at) > new Date(Date.now() + 5 * 60 * 1000)) {
    return tokens.access_token;
  }
  const refreshed = await refreshGoogleToken(env, tokens.refresh_token);
  const newExpiry = new Date(Date.now() + refreshed.expires_in * 1000).toISOString();
  await saveGoogleTokens(env, refreshed.access_token, tokens.refresh_token, newExpiry);
  return refreshed.access_token;
}

async function callGoogleCalendar(env, method, path, body = null) {
  const accessToken = await getValidAccessToken(env);
  if (!accessToken) throw new Error("Not connected to Google Calendar");
  const res = await fetch(`https://www.googleapis.com/calendar/v3${path}`, {
    method,
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : null,
  });
  if (res.status === 204) return { success: true };
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Google Calendar error ${res.status}: ${err}`);
  }
  return res.json();
}

async function saveMemory(env, sessionId, summary) {
  try {
    await supabase(env, "POST", "nova_memory", {
      session_id: sessionId,
      summary,
      created_at: new Date().toISOString(),
    });
    const all = await supabase(env, "GET", "nova_memory?select=id&order=created_at.desc");
    if (all && all.length > 60) {
      const toDelete = all.slice(60).map(r => r.id);
      for (const id of toDelete) {
        await supabase(env, "DELETE", `nova_memory?id=eq.${id}`).catch(() => {});
      }
    }
    return { success: true };
  } catch (e) {
    return { error: e.message };
  }
}

async function getMemories(env, limit = 30) {
  try {
    const rows = await supabase(env, "GET",
      `nova_memory?select=session_id,summary,created_at&order=created_at.desc&limit=${limit}`
    );
    return rows || [];
  } catch {
    return [];
  }
}

async function tavilySearch(env, query, maxResults = 5) {
  const res = await fetch("https://api.tavily.com/search", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      api_key: env.TAVILY_KEY,
      query,
      search_depth: "basic",
      max_results: maxResults,
      include_answer: true,
    }),
  });
  if (!res.ok) throw new Error(`Tavily ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return {
    answer: data.answer || null,
    results: (data.results || []).map(r => ({
      title: r.title,
      url: r.url,
      content: r.content?.slice(0, 400),
    })),
  };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const url    = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (url.pathname === "/oauth/callback" && request.method === "GET") {
      const code  = url.searchParams.get("code");
      const error = url.searchParams.get("error");
      if (error || !code) {
        return new Response(`<html><body><h2>Connection failed: ${error || "no code"}</h2><p><a href="${ALLOWED_ORIGIN}/Nova-Dashboard">Go back</a></p></body></html>`,
          { headers: { "Content-Type": "text/html" } });
      }
      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri: `${WORKER_URL}/oauth/callback`,
          grant_type: "authorization_code",
        }),
      });
      const tokens = await tokenRes.json();
      if (tokens.error) {
        return new Response(`<html><body><h2>Auth failed: ${tokens.error}</h2><p><a href="${ALLOWED_ORIGIN}/Nova-Dashboard">Go back</a></p></body></html>`,
          { headers: { "Content-Type": "text/html" } });
      }
      const expiresAt = new Date(Date.now() + tokens.expires_in * 1000).toISOString();
      await saveGoogleTokens(env, tokens.access_token, tokens.refresh_token, expiresAt);
      return Response.redirect(`${ALLOWED_ORIGIN}/Nova-Dashboard?cal=connected`, 302);
    }

    if (origin && origin !== ALLOWED_ORIGIN && url.pathname !== "/hash") {
      return jsonResponse({ error: "Forbidden" }, 403, origin);
    }

    if (request.method !== "POST") {
      return jsonResponse({ error: "Method not allowed" }, 405, origin);
    }

    let body;
    try { body = await request.json(); }
    catch { return jsonResponse({ error: "Invalid JSON" }, 400, origin); }

    const action = body.action || url.pathname.replace("/", "");

    if (action === "hash") {
      const { password } = body;
      if (!password) return jsonResponse({ error: "Password required" }, 400, origin);
      const salt = generateToken(16);
      const hash = await hashPassword(password, salt);
      return jsonResponse({ hash: `${salt}:${hash}`, instructions: "Save as PASSWORD_HASH secret." }, 200, origin);
    }

    if (action === "login") {
      const { password } = body;
      if (!password) return jsonResponse({ error: "Password required" }, 400, origin);
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const attempts = await checkRateLimit(env, ip);
      if (attempts >= RATE_LIMIT_MAX) {
        return jsonResponse({ error: `Too many attempts. Wait ${RATE_LIMIT_MINS} minutes.`, locked: true }, 429, origin);
      }
      const [salt, storedHash] = (env.PASSWORD_HASH || "").split(":");
      if (!salt || !storedHash) return jsonResponse({ error: "Server misconfigured" }, 500, origin);
      const inputHash = await hashPassword(password, salt);
      const correct   = inputHash === storedHash;
      await recordAttempt(env, ip, correct);
      if (!correct) {
        const remaining = RATE_LIMIT_MAX - attempts - 1;
        return jsonResponse({ error: `Incorrect password. ${remaining} attempt${remaining !== 1 ? "s" : ""} remaining.`, remaining }, 401, origin);
      }
      const token     = generateToken(64);
      const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000).toISOString();
      await supabase(env, "POST", "sessions", { token, expires_at: expiresAt, created_at: new Date().toISOString() });
      return jsonResponse({ token, expiresAt, success: true }, 200, origin);
    }

    if (action === "logout") {
      const token = request.headers.get("X-Session-Token") || body.token;
      if (token) await supabase(env, "DELETE", `sessions?token=eq.${encodeURIComponent(token)}`).catch(() => {});
      return jsonResponse({ success: true }, 200, origin);
    }

    if (action === "validate") {
      const token = request.headers.get("X-Session-Token") || body.token;
      return jsonResponse({ valid: await validateSession(env, token) }, 200, origin);
    }

    if (action === "google_auth_url") {
      const token = request.headers.get("X-Session-Token") || body.token;
      if (!await validateSession(env, token)) return jsonResponse({ error: "Unauthorized" }, 401, origin);
      const params = new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        redirect_uri: `${WORKER_URL}/oauth/callback`,
        response_type: "code",
        scope: GOOGLE_SCOPES,
        access_type: "offline",
        prompt: "consent",
      });
      return jsonResponse({ url: `https://accounts.google.com/o/oauth2/v2/auth?${params}` }, 200, origin);
    }

    if (action === "google_status") {
      const token = request.headers.get("X-Session-Token") || body.token;
      if (!await validateSession(env, token)) return jsonResponse({ error: "Unauthorized" }, 401, origin);
      const tokens = await getGoogleTokens(env);
      return jsonResponse({ connected: !!tokens }, 200, origin);
    }

    if (action === "google_disconnect") {
      const token = request.headers.get("X-Session-Token") || body.token;
      if (!await validateSession(env, token)) return jsonResponse({ error: "Unauthorized" }, 401, origin);
      await supabase(env, "DELETE", "google_tokens?id=eq.1").catch(() => {});
      return jsonResponse({ success: true }, 200, origin);
    }

    if (action === "calendar_events") {
      const token = request.headers.get("X-Session-Token") || body.token;
      if (!await validateSession(env, token)) return jsonResponse({ error: "Unauthorized" }, 401, origin);
      try {
        const params = new URLSearchParams({
          timeMin: body.timeMin || new Date().toISOString(),
          timeMax: body.timeMax || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
          singleEvents: "true",
          orderBy: "startTime",
          maxResults: "50",
        });
        const data = await callGoogleCalendar(env, "GET", `/calendars/primary/events?${params}`);
        const events = (data.items || []).map(e => ({
          id: e.id,
          title: e.summary || "Untitled",
          start: e.start?.dateTime || e.start?.date,
          end: e.end?.dateTime || e.end?.date,
          description: e.description || "",
          location: e.location || "",
        }));
        return jsonResponse({ events }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: err.message, notConnected: err.message.includes("Not connected") }, 500, origin);
      }
    }

    if (action === "calendar_add") {
      const token = request.headers.get("X-Session-Token") || body.token;
      if (!await validateSession(env, token)) return jsonResponse({ error: "Unauthorized" }, 401, origin);
      const { title, date, time, duration_minutes = 60, description = "" } = body;
      if (!title || !date) return jsonResponse({ error: "Title and date required", success: false }, 400, origin);
      try {
        const timeStr  = (time || "09:00").slice(0, 5);
        const startISO = `${date}T${timeStr}:00`;
        const startMs  = new Date(startISO).getTime();
        if (isNaN(startMs)) {
          return jsonResponse({ error: `Invalid date/time: ${date} ${timeStr}`, success: false }, 400, origin);
        }
        const endISO = new Date(startMs + duration_minutes * 60000).toISOString();
        const event = await callGoogleCalendar(env, "POST", "/calendars/primary/events", {
          summary: title,
          description,
          start: { dateTime: startISO, timeZone: "America/Toronto" },
          end:   { dateTime: endISO,   timeZone: "America/Toronto" },
        });
        return jsonResponse({ success: true, eventId: event.id, event: { id: event.id, title, start: startISO, end: endISO } }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: err.message, success: false }, 500, origin);
      }
    }

    if (action === "calendar_delete") {
      const token = request.headers.get("X-Session-Token") || body.token;
      if (!await validateSession(env, token)) return jsonResponse({ error: "Unauthorized" }, 401, origin);
      const { eventId } = body;
      if (!eventId) return jsonResponse({ error: "eventId required", success: false }, 400, origin);
      try {
        await callGoogleCalendar(env, "DELETE", `/calendars/primary/events/${eventId}`);
        return jsonResponse({ success: true }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: err.message, success: false }, 500, origin);
      }
    }

    if (action === "calendar_update") {
      const token = request.headers.get("X-Session-Token") || body.token;
      if (!await validateSession(env, token)) return jsonResponse({ error: "Unauthorized" }, 401, origin);
      const { eventId, title, date, time, duration_minutes = 60 } = body;
      if (!eventId) return jsonResponse({ error: "eventId required", success: false }, 400, origin);
      try {
        const timeStr  = (time || "09:00").slice(0, 5);
        const startISO = `${date}T${timeStr}:00`;
        const endISO   = new Date(new Date(startISO).getTime() + duration_minutes * 60000).toISOString();
        const event = await callGoogleCalendar(env, "PATCH", `/calendars/primary/events/${eventId}`, {
          summary: title,
          start: { dateTime: startISO, timeZone: "America/Toronto" },
          end:   { dateTime: endISO,   timeZone: "America/Toronto" },
        });
        return jsonResponse({ success: true, event }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: err.message, success: false }, 500, origin);
      }
    }

    if (action === "nova_save_memory") {
      const token = request.headers.get("X-Session-Token") || body.token;
      if (!await validateSession(env, token)) return jsonResponse({ error: "Unauthorized" }, 401, origin);
      const { session_id, summary } = body;
      if (!session_id || !summary) return jsonResponse({ error: "session_id and summary required" }, 400, origin);
      const result = await saveMemory(env, session_id, summary);
      return jsonResponse(result, result.error ? 500 : 200, origin);
    }

    if (action === "nova_get_memories") {
      const token = request.headers.get("X-Session-Token") || body.token;
      if (!await validateSession(env, token)) return jsonResponse({ error: "Unauthorized" }, 401, origin);
      const memories = await getMemories(env, body.limit || 30);
      return jsonResponse({ memories }, 200, origin);
    }

    if (action === "search_web") {
      const token = request.headers.get("X-Session-Token") || body.token;
      if (!await validateSession(env, token)) return jsonResponse({ error: "Unauthorized" }, 401, origin);
      const { query, max_results = 5 } = body;
      if (!query) return jsonResponse({ error: "query required" }, 400, origin);
      if (!env.TAVILY_KEY) return jsonResponse({ error: "TAVILY_KEY not configured" }, 500, origin);
      try {
        const results = await tavilySearch(env, query, max_results);
        return jsonResponse({ success: true, ...results }, 200, origin);
      } catch (err) {
        return jsonResponse({ error: err.message, success: false }, 500, origin);
      }
    }

    if (action === "ai") {
      const token = request.headers.get("X-Session-Token") || body.token;
      if (!await validateSession(env, token)) return jsonResponse({ error: "Unauthorized" }, 401, origin);
      const { messages, ...opts } = body.payload || {};
      if (!messages) return jsonResponse({ error: "No messages" }, 400, origin);
      let anthropicRes;
      try {
        anthropicRes = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": env.ANTHROPIC_KEY,
            "anthropic-version": "2023-06-01",
          },
          body: JSON.stringify({ messages, ...opts }),
        });
      } catch {
        return jsonResponse({ error: "Failed to reach Anthropic" }, 502, origin);
      }
      const data = await anthropicRes.json();
      return new Response(JSON.stringify(data), {
        status: anthropicRes.status,
        headers: { "Content-Type": "application/json", ...corsHeaders(origin) },
      });
    }

    return jsonResponse({ error: "Unknown action" }, 400, origin);
  },
};
