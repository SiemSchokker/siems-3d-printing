
const GITHUB_API = "https://api.github.com";
const DATA_PATH = "data/prints.json";
const ALLOWED_ORIGIN = "https://siemschokker.github.io";

function json(data, status = 200, origin = null) {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Vary": "Origin"
  };

  if (origin === ALLOWED_ORIGIN) {
    headers["Access-Control-Allow-Origin"] = origin;
  }

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );

  return base64url(new Uint8Array(signature));
}

async function createSession(env) {
  const payload = base64url(
    new TextEncoder().encode(JSON.stringify({
      expires: Date.now() + 8 * 60 * 60 * 1000
    }))
  );

  return payload + "." + await sign(payload, env.SESSION_SECRET);
}

async function verifySession(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  const token = authorization.replace(/^Bearer\s+/i, "");
  const parts = token.split(".");

  if (parts.length !== 2) return false;

  const expected = await sign(parts[0], env.SESSION_SECRET);

  if (parts[1] !== expected) return false;

  try {
    const payload = JSON.parse(
      new TextDecoder().decode(fromBase64url(parts[0]))
    );

    return payload.expires > Date.now();
  } catch {
    return false;
  }
}

async function githubRequest(env, method = "GET", body = null) {
  const url = `${GITHUB_API}/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents/${DATA_PATH}`;

  const response = await fetch(url, {
    method,
    headers: {
      "Authorization": `Bearer ${env.GITHUB_TOKEN}`,
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
      "User-Agent": "Siems-3D-Printing"
    },
    body: body ? JSON.stringify(body) : undefined
  });

  const text = await response.text();
  let data = {};

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new Error("GitHub gaf een ongeldig antwoord.");
  }

  if (!response.ok && response.status !== 404) {
    throw new Error(data.message || "GitHub kon de gegevens niet verwerken.");
  }

  return { response, data };
}

async function getPrints(env) {
  const { response, data } = await githubRequest(env);

  if (response.status === 404) {
    return { prints: [], sha: null };
  }

  const bytes = Uint8Array.from(
    atob(data.content.replace(/\s/g, "")),
    c => c.charCodeAt(0)
  );

  const content = new TextDecoder().decode(bytes);
  const parsed = JSON.parse(content);

  return {
    prints: Array.isArray(parsed) ? parsed : [],
    sha: data.sha
  };
}

async function savePrints(env, prints, sha) {
  const content = JSON.stringify(prints, null, 2);
  const bytes = new TextEncoder().encode(content);

  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);

  const body = {
    message: "Prints bijgewerkt via Siems 3D Printing dashboard",
    content: btoa(binary),
    branch: "main"
  };

  if (sha) body.sha = sha;

  await githubRequest(env, "PUT", body);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");

    if (origin && origin !== ALLOWED_ORIGIN) {
      return json({ error: "Geen toegang vanaf deze website." }, 403);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
          "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "86400",
          "Vary": "Origin"
        }
      });
    }

    try {
      const url = new URL(request.url);
      const path = url.pathname;

      if (!env.ADMIN_PASSWORD ||
          !env.SESSION_SECRET ||
          !env.GITHUB_TOKEN ||
          !env.GITHUB_OWNER ||
          !env.GITHUB_REPO) {
        return json({ error: "Worker-instellingen ontbreken." }, 500, origin);
      }

      if (path === "/" && request.method === "GET") {
        return json({
          status: "online",
          name: "Siems 3D Printing API"
        }, 200, origin);
      }

      if (path === "/api/login" && request.method === "POST") {
        const body = await request.json();

        if (typeof body.password !== "string" ||
            body.password !== env.ADMIN_PASSWORD) {
          return json({ error: "Onjuist wachtwoord." }, 401, origin);
        }

        return json({
          token: await createSession(env)
        }, 200, origin);
      }

      if (!await verifySession(request, env)) {
        return json({ error: "Sessie verlopen. Log opnieuw in." }, 401, origin);
      }

      if (path === "/api/prints" && request.method === "GET") {
        const data = await getPrints(env);
        return json({ prints: data.prints }, 200, origin);
      }

      if (path === "/api/prints" && request.method === "POST") {
        const body = await request.json();

        if (typeof body.name !== "string" ||
            typeof body.description !== "string" ||
            !body.name.trim() ||
            !body.description.trim() ||
            body.name.length > 120 ||
            body.description.length > 2000 ||
            (body.image && (
              typeof body.image !== "string" ||
              body.image.length > 2048 ||
              !/^https:\/\//i.test(body.image)
            ))) {
          return json({ error: "Controleer de ingevulde gegevens." }, 400, origin);
        }

        const data = await getPrints(env);

        data.prints.push({
          id: crypto.randomUUID(),
          name: body.name.trim(),
          description: body.description.trim(),
          image: body.image || ""
        });

        await savePrints(env, data.prints, data.sha);

        return json({ success: true }, 201, origin);
      }

      if (path.startsWith("/api/prints/") && request.method === "DELETE") {
        const id = decodeURIComponent(path.slice("/api/prints/".length));

        if (!id || id.includes("/")) {
          return json({ error: "Ongeldig print-ID." }, 400, origin);
        }

        const data = await getPrints(env);
        const updated = data.prints.filter(print => print.id !== id);

        if (updated.length === data.prints.length) {
          return json({ error: "Print niet gevonden." }, 404, origin);
        }

        await savePrints(env, updated, data.sha);

        return json({ success: true }, 200, origin);
      }

      return json({ error: "Pagina niet gevonden." }, 404, origin);

    } catch (error) {
      return json({
        error: error.message || "Er is een serverfout opgetreden."
      }, 500, origin);
    }
  }
};
