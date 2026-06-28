// cherm-edge — the Cloudflare Worker behind cherm.chat and plugins.cherm.chat.
//
//  cherm.chat            — installers, release artifacts, version metadata, docs.
//  plugins.cherm.chat    — the official plugin store: serve manifests/packages
//                          from R2 and accept community submissions.
//
// Bindings (wrangler.toml):
//   DIST     R2 bucket  cherm-dist     (install scripts, version.json, releases/*)
//   PLUGINS  R2 bucket  cherm-plugins  (plugin index/manifests/packages, submissions)
//   SUBMIT_TOKEN (optional secret) — if set, /submit requires header
//                x-cherm-submit-token to match (anti-abuse; submissions are still
//                always stored as community_unaudited).
//
// Trust model: a submitted plugin is ALWAYS forced to community_unaudited
// (use-at-your-own-risk) — the submitter cannot self-declare official/audited.
// Official plugins (e.g. pastel-theme) are published directly to R2 by the
// project, never via /submit.

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "access-control-allow-origin": "*",
  "cache-control": "no-store",
};

// Permissions a plugin may declare (mirrors core/src/plugins.rs — defense in depth).
const ALLOWED_PERMISSIONS = new Set([
  "tui.theme", "tui.widget", "tui.statusbar", "tui.panel", "tui.renderer", "tui.command",
  "notify",
  "wallet.read.status", "wallet.read.address", "wallet.read.balance", "wallet.convert.fiat",
]);

function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { ...JSON_HEADERS, ...extra } });
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function safeName(name) {
  return String(name || "")
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, "-")
    .replace(/^[.\-_]+|[.\-_]+$/g, "");
}

// Serve an R2 object, passing through its stored content type (default applied).
async function serveR2(bucket, key, defaultType) {
  const obj = await bucket.get(key);
  if (!obj) return json({ error: "not_found", key }, 404);
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  if (!headers.has("content-type")) headers.set("content-type", defaultType || "application/octet-stream");
  headers.set("access-control-allow-origin", "*");
  if (key.startsWith("releases/")) headers.set("cache-control", "public, max-age=300");
  // Content-hashed landing assets (Vite emits /assets/*-<hash>.js|css) + fonts +
  // images never change for a given URL, so cache them hard. index.html stays
  // fresh so a new deploy is picked up immediately.
  else if (key.startsWith("assets/") || key.startsWith("fonts/") || /\.(woff2?|ttf|otf|png|jpe?g|webp|svg|ico)$/.test(key))
    headers.set("cache-control", "public, max-age=31536000, immutable");
  else headers.set("cache-control", "no-store");
  return new Response(obj.body, { headers });
}

// ---- plugins.cherm.chat ----------------------------------------------------

async function handlePlugins(request, env, url) {
  const path = url.pathname.replace(/^\/+/, "");

  if (request.method === "POST" && path === "submit") return handleSubmit(request, env);

  if (request.method !== "GET" && request.method !== "HEAD") {
    return json({ error: "method_not_allowed" }, 405);
  }

  if (path === "" || path === "index" || path === "index.json") {
    const obj = await env.PLUGINS.get("index");
    if (!obj) return json({ plugins: [] });
    return serveR2(env.PLUGINS, "index", "application/json");
  }

  // /{plugin}/manifest | /{plugin}/package | /{plugin}/releases/{ver}/{manifest|package}
  if (/^[a-z0-9._-]+\/(manifest|package)$/.test(path) ||
      /^[a-z0-9._-]+\/releases\/[a-z0-9.+_-]+\/(manifest|package)$/.test(path)) {
    return serveR2(env.PLUGINS, path, "application/json");
  }

  return json({ error: "not_found" }, 404);
}

async function handleSubmit(request, env) {
  // Admin token: when configured it gates ALL submissions; possessing it also
  // authorizes updating an existing plugin. Without it, submissions are open but
  // may only CREATE new names (never overwrite — see the collision check below).
  const hasToken = !!env.SUBMIT_TOKEN &&
    request.headers.get("x-cherm-submit-token") === env.SUBMIT_TOKEN;
  if (env.SUBMIT_TOKEN && !hasToken) return json({ error: "unauthorized" }, 401);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "bad_json" }, 400);
  }
  const manifest = body && body.manifest;
  const pkg = (body && body.package) || {};
  if (!manifest || !manifest.name || !manifest.version) {
    return json({ error: "name and version are required" }, 400);
  }

  const name = safeName(manifest.name);
  if (!name) return json({ error: "invalid plugin name" }, 400);

  // Permission gate (deny-by-default), mirroring the client/core.
  const perms = Array.isArray(manifest.permissions) ? manifest.permissions : [];
  for (const p of perms) {
    if (!ALLOWED_PERMISSIONS.has(String(p))) {
      return json({ error: `permission '${p}' is not allowed` }, 400);
    }
  }

  // Load the catalog FIRST and block name collisions: an open (no-token)
  // submission must never overwrite an existing plugin — otherwise anyone could
  // hijack `pastel-theme` (or any community plugin) by re-submitting its name.
  // Only an authenticated admin may update an existing entry.
  let index = { plugins: [] };
  const idxObj = await env.PLUGINS.get("index");
  if (idxObj) {
    try { index = await idxObj.json(); } catch { index = { plugins: [] }; }
  }
  if (!Array.isArray(index.plugins)) index.plugins = [];
  if (index.plugins.some((p) => p.name === name) && !hasToken) {
    return json({ error: `plugin name '${name}' already exists — choose a unique name` }, 409);
  }

  // Canonical package bytes + integrity hash.
  const pkgBytes = new TextEncoder().encode(JSON.stringify(pkg));
  const hash = await sha256Hex(pkgBytes);

  // The submitter cannot self-declare official/audited.
  const clean = {
    name,
    display_name: manifest.display_name || name,
    version: String(manifest.version),
    kind: manifest.kind || "theme",
    category: "community_unaudited",
    description: manifest.description || "",
    author: manifest.author || "",
    license: manifest.license || "",
    source_url: manifest.source_url || "",
    permissions: perms,
    min_client: manifest.min_client || "0.1.0",
    package_sha256: hash,
    updated_ts: Date.now(),
  };
  const manifestBytes = new TextEncoder().encode(JSON.stringify(clean, null, 2));

  // Store current + versioned objects.
  const ct = { httpMetadata: { contentType: "application/json" } };
  await env.PLUGINS.put(`${name}/manifest`, manifestBytes, ct);
  await env.PLUGINS.put(`${name}/package`, pkgBytes, ct);
  await env.PLUGINS.put(`${name}/releases/${clean.version}/manifest`, manifestBytes, ct);
  await env.PLUGINS.put(`${name}/releases/${clean.version}/package`, pkgBytes, ct);

  // Update the catalog index (loaded above). An admin re-submit replaces the
  // existing entry; an open submission only ever adds a new (unique) name.
  index.plugins = index.plugins.filter((p) => p.name !== name);
  index.plugins.push(clean);
  await env.PLUGINS.put("index", new TextEncoder().encode(JSON.stringify(index, null, 2)), ct);

  return json({ ok: true, name, version: clean.version, category: "community_unaudited" });
}

// ---- cherm.chat ------------------------------------------------------------

const INSTALL_FILES = {
  "install.sh": "text/x-shellscript; charset=utf-8",
  "install.ps1": "text/plain; charset=utf-8",
  "server-install.sh": "text/x-shellscript; charset=utf-8",
  "server-install.ps1": "text/plain; charset=utf-8",
};

async function handleDist(request, env, url) {
  const path = url.pathname.replace(/^\/+/, "");

  if (path in INSTALL_FILES) return serveR2(env.DIST, path, INSTALL_FILES[path]);
  if (path === "version.json") return serveR2(env.DIST, "version.json", "application/json");
  if (path.startsWith("releases/")) return serveR2(env.DIST, path, "application/octet-stream");
  if (path === "signatures") return new Response(SIGNATURES_HTML, { headers: { "content-type": "text/html; charset=utf-8" } });
  // Landing site (web/dist) is uploaded to R2. Root serves index.html; every
  // other path is looked up as a static asset (assets/*, fonts/*, images, …).
  const key = (path === "" || path === "docs") ? "index.html" : path;
  return serveR2(env.DIST, key, "application/octet-stream");
}

const SIGNATURES_HTML = `<!doctype html><meta charset=utf-8><title>Cherm attestation tiers</title>
<style>body{background:#17191d;color:#fff;font:16px/1.6 ui-monospace,monospace;max-width:46rem;margin:6vh auto;padding:0 1.2rem}h1{color:#ff007b}.g{color:#2ecc71}.y{color:#f1c40f}.r{color:#e74c3c}</style>
<h1>Server attestation</h1>
<p>Before connecting, the client asks a server to prove what code it runs:</p>
<p><span class=g>🟢 green</span> — a hardware TEE (AWS Nitro) proves the running code matches the official build.</p>
<p><span class=y>🟡 yellow</span> — a genuine official release hash signed by the project key. Does not prove the server actually runs it (replayable). The official <code>srv.cherm.chat</code> on a normal VPS is yellow.</p>
<p><span class=r>🔴 red</span> — unsigned, or the hash does not match the official public codebase.</p>
<p>Pure software can't prove its own integrity; only a TEE makes it unforgeable. See <a href="https://github.com/ctresb/cherm/blob/main/ATTESTATION.md">ATTESTATION.md</a>.</p>`;

// ---- router ----------------------------------------------------------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const host = url.hostname;
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET,POST,OPTIONS",
          "access-control-allow-headers": "content-type,x-cherm-submit-token",
        },
      });
    }
    try {
      if (host.startsWith("plugins.")) return await handlePlugins(request, env, url);
      return await handleDist(request, env, url);
    } catch (e) {
      return json({ error: "internal", message: String(e) }, 500);
    }
  },
};
