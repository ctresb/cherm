//! Plugin system (architecture_specification §6, §10).
//!
//! Cherm has no separate theme system — *everything extensible is a plugin*, and
//! a theme is just a plugin that ships a palette. Plugins are **declarative data**
//! (a signed manifest + a package describing a theme / widgets / renderer rules),
//! never arbitrary code, so they are sandboxed by construction: a plugin can only
//! express the safe, bounded TUI extensions the client knows how to render. It can
//! never reach privileged surfaces (wallet core, confirmation UI, notification
//! bypass, system/official UI impersonation) because there is no way to *say* that
//! in the format and the permission validator rejects it anyway.
//!
//! Trust tiers (shown to the user before install):
//!   * `official`             — maintained / approved by Cherm.
//!   * `community_audited`     — public source reviewed & accepted by Cherm.
//!   * `community_unaudited`   — submitted, not yet reviewed → use at your own risk.
//!
//! The category is authoritative from the official store; a submission always
//! lands as `community_unaudited` server-side.
//!
//! Local layout under `~/.cherm/plugins/`:
//!   * `<name>/manifest.json`, `<name>/package.json`  — verified, installed plugin
//!   * `installed.json`     — index of installed plugins (+ which theme is active)
//!   * `active-theme.json`  — the palette the TUI reads at startup (and on events)
//!   * `active-widgets.json`— declarative widgets the TUI renders

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::ipc::Events;

/// Default official store base. Overridable for testing via `CHERM_PLUGINS_URL`.
const DEFAULT_STORE: &str = "https://plugins.cherm.chat";

/// Network timeouts for store/update HTTP. Without these a network attacker (or a
/// dead store) that completes the TCP handshake but never sends data wedges the
/// ENTIRE core, which dispatches commands sequentially and awaits each inline.
const HTTP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Max bytes we will read from a store/manifest/package response. The declarative
/// plugin format is tiny; this caps a compromised store from OOM-ing the core with
/// a multi-GB body.
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_PACKAGE_BYTES: usize = 4 * 1024 * 1024;

/// Read a response body with a hard byte cap (rejecting an over-large or lying
/// `Content-Length`, and streaming so a chunked body can't exceed the cap either).
async fn read_capped(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len as usize > max {
            bail!("response too large ({len} bytes > {max})");
        }
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| anyhow!("read body: {e}"))? {
        if buf.len() + chunk.len() > max {
            bail!("response exceeded {max} bytes");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

// ===========================================================================
// Permission model — deny by default
// ===========================================================================

/// The only permissions a plugin may ever hold. Anything outside this set is
/// rejected at install/submit time. Wallet permissions are READ-ONLY and
/// granular (a price-conversion plugin never receives address/balance data it
/// does not need).
pub const ALLOWED_PERMISSIONS: &[&str] = &[
    // safe TUI surfaces
    "tui.theme",
    "tui.widget",
    "tui.statusbar",
    "tui.panel",
    "tui.renderer",
    "tui.command",
    // notifications go THROUGH the notification core (never a bypass)
    "notify",
    // read-only, granular wallet display helpers (architecture_specification §6.7)
    "wallet.read.status",
    "wallet.read.address",
    "wallet.read.balance",
    "wallet.convert.fiat",
];

/// Capabilities a plugin may NEVER request. Listed explicitly so a submission
/// asking for them is rejected with a clear reason rather than a generic
/// "unknown permission". These map 1:1 to the forbidden list in
/// architecture_specification §6.7 / §10.
pub const FORBIDDEN_PERMISSIONS: &[&str] = &[
    "wallet.read.seed",
    "wallet.read.privatekey",
    "wallet.read.privatekeys",
    "wallet.sign",
    "wallet.send",
    "wallet.broadcast",
    "wallet.write",
    "wallet.address.modify",
    "wallet.destination.modify",
    "wallet.fees.hide",
    "wallet.confirm",
    "wallet.confirm.modify",
    "wallet.core",
    "notify.bypass",
    "ui.system",
    "ui.official",
];

/// Human-readable explanation of a permission (shown before install).
pub fn permission_help(p: &str) -> &'static str {
    match p {
        "tui.theme" => "change the color theme",
        "tui.widget" => "add a small TUI widget (clock / status indicator)",
        "tui.statusbar" => "add an item to the status bar",
        "tui.panel" => "add an optional side panel",
        "tui.renderer" => "render custom previews for matching messages",
        "tui.command" => "add a safe local-only utility command",
        "notify" => "request notifications through the notification core",
        "wallet.read.status" => "read-only: show whether a wallet is configured",
        "wallet.read.address" => "read-only: show an approved public wallet address",
        "wallet.read.balance" => "read-only: show an approved balance",
        "wallet.convert.fiat" => "read-only: convert a visible balance to fiat",
        _ => "unknown permission",
    }
}

/// Validate a plugin's declared permissions. Deny-by-default: every permission
/// must be on [`ALLOWED_PERMISSIONS`]; any explicitly-forbidden capability (or
/// any unknown `wallet.*`) is rejected. This is the enforcement point for the
/// wallet-safety and plugin-safety rules.
pub fn validate_permissions(perms: &[String]) -> Result<()> {
    for p in perms {
        let p = p.trim();
        if FORBIDDEN_PERMISSIONS.contains(&p) {
            bail!("permission '{p}' is forbidden for plugins (privileged/unsafe)");
        }
        // No wallet permission outside the read-only allow-list, ever.
        if p.starts_with("wallet.") && !ALLOWED_PERMISSIONS.contains(&p) {
            bail!(
                "wallet permission '{p}' is not allowed — wallet access is read-only and limited"
            );
        }
        if !ALLOWED_PERMISSIONS.contains(&p) {
            bail!("permission '{p}' is not recognised");
        }
    }
    Ok(())
}

// ===========================================================================
// Manifest + package format
// ===========================================================================

/// Public, machine-readable plugin metadata. Served at
/// `plugins.cherm.chat/{name}/manifest` and `…/releases/{version}/manifest`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub name: String,
    #[serde(default)]
    pub display_name: String,
    pub version: String,
    /// theme | widget | renderer | command | panel | bundle
    #[serde(default)]
    pub kind: String,
    /// official | community_audited | community_unaudited (authoritative: store)
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub license: String,
    /// Public source/codebase link (required by the open-source store rule).
    #[serde(default)]
    pub source_url: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub min_client: String,
    /// Hex SHA-256 of the package bytes — integrity for download + update.
    #[serde(default)]
    pub package_sha256: String,
    #[serde(default)]
    pub updated_ts: i64,
}

/// The plugin payload. Served at `plugins.cherm.chat/{name}/package`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Package {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theme: Option<Theme>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub widgets: Vec<Widget>,
}

/// A declarative palette. Every field is optional — present fields override the
/// client default; absent fields keep the default magenta→pink base.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Theme {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magenta: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pink: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dark: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub white: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub border: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub muted: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub green: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yellow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub red: Option<String>,
}

/// A declarative TUI widget. The client renders only the slots/kinds it knows;
/// an unknown slot/kind is ignored (bounded by the client per §6.5).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Widget {
    /// top_left | top_right | status
    pub slot: String,
    /// clock | text
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Go time layout for `kind == "clock"` (e.g. "15:04:05").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// The store index served at `plugins.cherm.chat/index`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoreIndex {
    #[serde(default)]
    pub plugins: Vec<Manifest>,
}

/// Local record of one installed plugin.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Installed {
    pub manifest: Manifest,
    #[serde(default)]
    pub active: bool,
}

/// `installed.json` — the index of installed plugins.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstalledIndex {
    #[serde(default)]
    pub plugins: Vec<Installed>,
}

// ===========================================================================
// Plugins manager (global; not per-server)
// ===========================================================================

pub struct Plugins {
    dir: PathBuf,
    store: String,
    http: reqwest::Client,
    events: Events,
}

impl Plugins {
    pub fn new(home: &Path, events: Events) -> Self {
        let dir = home.join("plugins");
        let _ = std::fs::create_dir_all(&dir);
        let store = std::env::var("CHERM_PLUGINS_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_STORE.to_string());
        let http = reqwest::Client::builder()
            .user_agent(concat!("cherm-core/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_TIMEOUT)
            .build()
            .unwrap_or_default();
        Plugins {
            dir,
            store,
            http,
            events,
        }
    }

    // -- paths --------------------------------------------------------------

    fn installed_path(&self) -> PathBuf {
        self.dir.join("installed.json")
    }
    fn active_theme_path(&self) -> PathBuf {
        self.dir.join("active-theme.json")
    }
    fn active_widgets_path(&self) -> PathBuf {
        self.dir.join("active-widgets.json")
    }
    /// The on-disk directory for a plugin. FALLIBLE: names like `...`, `///`, or
    /// `--` sanitize to an empty segment, and `self.dir.join("")` is the plugins
    /// ROOT — a later `remove_dir_all` on that would wipe every plugin + the index.
    /// Reject an empty-sanitized name so the path is always a strict child.
    fn plugin_dir(&self, name: &str) -> Result<PathBuf> {
        let seg = sanitize(name);
        if seg.is_empty() {
            bail!("invalid plugin name {name:?}");
        }
        Ok(self.dir.join(seg))
    }

    fn load_installed(&self) -> InstalledIndex {
        std::fs::read_to_string(self.installed_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save_installed(&self, idx: &InstalledIndex) -> Result<()> {
        std::fs::write(self.installed_path(), serde_json::to_vec_pretty(idx)?)?;
        Ok(())
    }

    // -- startup ------------------------------------------------------------

    /// Emit the currently-active theme + widgets so the TUI applies them on
    /// connect (it also reads the files directly at startup for the first frame).
    pub fn emit_active(&self) {
        if let Ok(s) = std::fs::read_to_string(self.active_theme_path()) {
            if let Ok(palette) = serde_json::from_str::<Value>(&s) {
                self.events
                    .emit(json!({"event": "theme", "palette": palette}));
            }
        }
        if let Ok(s) = std::fs::read_to_string(self.active_widgets_path()) {
            if let Ok(widgets) = serde_json::from_str::<Value>(&s) {
                self.events
                    .emit(json!({"event": "widgets", "widgets": widgets}));
            }
        }
    }

    // -- store --------------------------------------------------------------

    /// Fetch the official store index and emit `store_plugins`.
    pub async fn list_store(&self) -> Result<()> {
        let url = format!("{}/index", self.store);
        let idx: StoreIndex = match self.http.get(&url).send().await {
            Ok(r) => read_capped(r, MAX_MANIFEST_BYTES)
                .await
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default(),
            Err(e) => {
                self.events.emit(json!({
                    "event": "error", "code": "store_unreachable",
                    "message": format!("could not reach the plugin store: {e}")
                }));
                return Ok(());
            }
        };
        let installed = self.load_installed();
        let plugins: Vec<Value> = idx
            .plugins
            .iter()
            .map(|m| manifest_to_value(m, &installed))
            .collect();
        self.events
            .emit(json!({"event": "store_plugins", "plugins": plugins}));
        Ok(())
    }

    /// Emit `installed_plugins` from local state.
    pub fn list_installed(&self) -> Result<()> {
        let installed = self.load_installed();
        let plugins: Vec<Value> = installed
            .plugins
            .iter()
            .map(|i| {
                let mut v = manifest_to_value(&i.manifest, &installed);
                v["active"] = json!(i.active);
                v["installed"] = json!(true);
                v
            })
            .collect();
        self.events
            .emit(json!({"event": "installed_plugins", "plugins": plugins}));
        Ok(())
    }

    /// Download, verify, and install a plugin from the official store, then
    /// activate it (apply its theme/widgets) and surface the result.
    pub async fn install(&self, name: &str) -> Result<()> {
        let name = name.trim();
        // Reject a name that doesn't map to a safe path segment up front (so we
        // never write into / later remove the plugins ROOT).
        let pdir = match self.plugin_dir(name) {
            Ok(p) => p,
            Err(_) => {
                self.events.emit(json!({
                    "event": "error", "code": "plugin_rejected",
                    "message": format!("invalid plugin name {name:?}")
                }));
                return Ok(());
            }
        };
        // 1. Fetch the manifest from the store (authoritative category).
        let manifest_url = format!("{}/{}/manifest", self.store, sanitize(name));
        let manifest_bytes = read_capped(
            self.http
                .get(&manifest_url)
                .send()
                .await
                .map_err(|e| anyhow!("fetch manifest: {e}"))?,
            MAX_MANIFEST_BYTES,
        )
        .await
        .map_err(|e| anyhow!("read manifest: {e}"))?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| anyhow!("parse manifest: {e}"))?;

        // 2. Bind the manifest to what we asked for: a store/CDN response for some
        // OTHER plugin must not be installed under (or overwrite the record of) the
        // requested name. The package/dir/record are all keyed on the requested
        // name, so the manifest's own name must match it.
        if manifest.name.trim() != name {
            self.events.emit(json!({
                "event": "error", "code": "plugin_rejected",
                "message": format!("store returned a manifest for {:?}, not {name:?}", manifest.name)
            }));
            return Ok(());
        }

        // 3. Permission gate (defense in depth — the store also enforces this).
        if let Err(e) = validate_permissions(&manifest.permissions) {
            self.events.emit(json!({
                "event": "error", "code": "plugin_rejected",
                "message": format!("{name} requests unsafe permissions: {e}")
            }));
            return Ok(());
        }

        // 4. Download the package and verify its SHA-256 against the manifest.
        let package_url = format!("{}/{}/package", self.store, sanitize(name));
        let bytes = read_capped(
            self.http
                .get(&package_url)
                .send()
                .await
                .map_err(|e| anyhow!("fetch package: {e}"))?,
            MAX_PACKAGE_BYTES,
        )
        .await
        .map_err(|e| anyhow!("read package: {e}"))?;
        let got = hex::encode(Sha256::digest(&bytes));
        // A manifest with no checksum cannot be verified — refuse to install it
        // rather than fall through (an empty hash must never bypass the check).
        if manifest.package_sha256.is_empty() {
            self.events.emit(json!({
                "event": "error", "code": "verify_failed",
                "message": format!("{name} has no package checksum — refusing to install an unverified plugin")
            }));
            return Ok(());
        }
        if got != manifest.package_sha256 {
            self.events.emit(json!({
                "event": "error", "code": "verify_failed",
                "message": format!("package checksum mismatch for {name} (expected {}, got {got})", manifest.package_sha256)
            }));
            return Ok(());
        }
        // Validate the package parses into the known declarative shape before we
        // store it (rejects garbage / non-conforming payloads).
        let _package: Package =
            serde_json::from_slice(&bytes).map_err(|e| anyhow!("parse package: {e}"))?;

        // 5. Persist verified files under the plugin dir (validated above).
        std::fs::create_dir_all(&pdir)?;
        std::fs::write(
            pdir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest)?,
        )?;
        std::fs::write(pdir.join("package.json"), &bytes)?;

        // 5. Record install (replacing any previous version).
        let mut idx = self.load_installed();
        idx.plugins.retain(|p| p.manifest.name != manifest.name);
        idx.plugins.push(Installed {
            manifest: manifest.clone(),
            active: true,
        });
        self.save_installed(&idx)?;

        // 6. Activate: apply theme + widgets and notify the TUI.
        self.apply_active(&idx)?;

        self.events.emit(json!({
            "event": "plugin_installed",
            "name": manifest.name,
            "version": manifest.version,
            "category": manifest.category,
        }));
        self.events.emit(json!({
            "event": "info",
            "message": format!("installed {} v{} ({})", manifest.name, manifest.version, manifest.category)
        }));
        self.list_installed()?;
        Ok(())
    }

    /// Remove an installed plugin and re-apply whatever remains active.
    pub fn remove(&self, name: &str) -> Result<()> {
        let mut idx = self.load_installed();
        let before = idx.plugins.len();
        idx.plugins.retain(|p| p.manifest.name != name);
        if idx.plugins.len() == before {
            self.events.emit(json!({
                "event": "error", "code": "not_installed",
                "message": format!("{name} is not installed")
            }));
            return Ok(());
        }
        // Only remove a VALID per-plugin directory; never let an empty-sanitized
        // name resolve to the plugins root and wipe everything.
        if let Ok(pdir) = self.plugin_dir(name) {
            let _ = std::fs::remove_dir_all(pdir);
        }
        self.save_installed(&idx)?;
        self.apply_active(&idx)?;
        self.events
            .emit(json!({"event": "info", "message": format!("removed {name}")}));
        self.list_installed()?;
        Ok(())
    }

    /// Recompute the active theme + widgets from installed plugins and write the
    /// `active-theme.json` / `active-widgets.json` files, emitting events so the
    /// TUI live-applies. The last active theme wins; widgets accumulate.
    fn apply_active(&self, idx: &InstalledIndex) -> Result<()> {
        let mut palette: Option<Theme> = None;
        let mut widgets: Vec<Widget> = Vec::new();
        for p in &idx.plugins {
            if !p.active {
                continue;
            }
            if let Ok(pkg) = self.load_package(&p.manifest.name) {
                if let Some(t) = pkg.theme {
                    palette = Some(t);
                }
                // Sanitize store-controlled widget strings before they reach the TUI.
                widgets.extend(pkg.widgets.into_iter().map(|mut w| {
                    w.value = w.value.map(|v| clean_display(&v, 256));
                    w.format = w.format.map(|v| clean_display(&v, 64));
                    w
                }));
            }
        }

        match &palette {
            Some(t) => {
                let v = theme_to_palette(t);
                std::fs::write(self.active_theme_path(), serde_json::to_vec_pretty(&v)?)?;
                self.events.emit(json!({"event": "theme", "palette": v}));
            }
            None => {
                let _ = std::fs::remove_file(self.active_theme_path());
                self.events
                    .emit(json!({"event": "theme", "palette": Value::Null}));
            }
        }
        std::fs::write(
            self.active_widgets_path(),
            serde_json::to_vec_pretty(&widgets)?,
        )?;
        self.events
            .emit(json!({"event": "widgets", "widgets": widgets}));
        Ok(())
    }

    fn load_package(&self, name: &str) -> Result<Package> {
        let s = std::fs::read_to_string(self.plugin_dir(name)?.join("package.json"))?;
        Ok(serde_json::from_str(&s)?)
    }

    /// Check the store for newer versions of installed plugins; emit one
    /// `plugin_update_available` per outdated plugin.
    pub async fn check_updates(&self) -> Result<()> {
        let idx = self.load_installed();
        let mut found = 0;
        for p in &idx.plugins {
            let url = format!("{}/{}/manifest", self.store, sanitize(&p.manifest.name));
            let latest: Manifest = match self.http.get(&url).send().await {
                Ok(r) => match read_capped(r, MAX_MANIFEST_BYTES).await {
                    Ok(b) => match serde_json::from_slice(&b) {
                        Ok(m) => m,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                },
                Err(_) => continue,
            };
            if is_newer(&latest.version, &p.manifest.version) {
                found += 1;
                self.events.emit(json!({
                    "event": "plugin_update_available",
                    "name": p.manifest.name,
                    "current": p.manifest.version,
                    "latest": latest.version,
                    "category": latest.category,
                }));
            }
        }
        self.events.emit(json!({
            "event": "info",
            "message": if found == 0 { "all plugins up to date".to_string() }
                       else { format!("{found} plugin update(s) available") }
        }));
        Ok(())
    }

    /// Submit a plugin to the official store. The package is sent to the store
    /// backend, which stores it under `plugins.cherm.chat/{name}/…` and marks it
    /// `community_unaudited` (use-at-your-own-risk) until a Cherm review promotes
    /// it. Local permission validation runs first so obviously-unsafe submissions
    /// fail fast.
    pub async fn submit(&self, mut manifest: Manifest, package: Value) -> Result<()> {
        if manifest.name.is_empty() || manifest.version.is_empty() {
            self.events.emit(json!({
                "event": "error", "code": "bad_submission",
                "message": "plugin name and version are required"
            }));
            return Ok(());
        }
        if let Err(e) = validate_permissions(&manifest.permissions) {
            self.events.emit(json!({
                "event": "error", "code": "plugin_rejected",
                "message": format!("submission requests unsafe permissions: {e}")
            }));
            return Ok(());
        }
        // The submitter cannot self-declare official/audited status.
        manifest.category = "community_unaudited".to_string();

        let url = format!("{}/submit", self.store);
        let body = json!({"manifest": manifest, "package": package});
        let mut req = self.http.post(&url).json(&body);
        if let Ok(tok) = std::env::var("CHERM_SUBMIT_TOKEN") {
            if !tok.is_empty() {
                req = req.header("x-cherm-submit-token", tok);
            }
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                let txt = resp.text().await.unwrap_or_default();
                if status.is_success() {
                    self.events.emit(json!({
                        "event": "plugin_submitted",
                        "name": manifest.name,
                        "version": manifest.version,
                        "category": "community_unaudited",
                    }));
                    self.events.emit(json!({
                        "event": "info",
                        "message": format!("submitted {} v{} — listed as community unaudited (use at your own risk) pending Cherm review", manifest.name, manifest.version)
                    }));
                } else {
                    self.events.emit(json!({
                        "event": "error", "code": "submit_failed",
                        "message": format!("store rejected submission ({status}): {txt}")
                    }));
                }
            }
            Err(e) => {
                self.events.emit(json!({
                    "event": "error", "code": "submit_failed",
                    "message": format!("could not reach the store: {e}")
                }));
            }
        }
        Ok(())
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Map a manifest to the wire shape the TUI consumes, annotating install state
/// and a per-permission explanation so the UI can show what a plugin can do.
fn manifest_to_value(m: &Manifest, installed: &InstalledIndex) -> Value {
    let is_installed = installed.plugins.iter().any(|p| p.manifest.name == m.name);
    let perms: Vec<Value> = m
        .permissions
        .iter()
        .map(|p| json!({"id": p, "help": permission_help(p)}))
        .collect();
    // Sanitize every store-controlled display string (terminal-escape injection).
    let disp = |s: &str, max: usize| clean_display(s, max);
    json!({
        "name": disp(&m.name, 64),
        "display_name": if m.display_name.is_empty() { disp(&m.name, 64) } else { disp(&m.display_name, 64) },
        "version": disp(&m.version, 32),
        "kind": disp(&m.kind, 32),
        "category": disp(&m.category, 32),
        "description": disp(&m.description, 2000),
        "author": disp(&m.author, 128),
        "license": disp(&m.license, 64),
        "source_url": disp(&m.source_url, 512),
        "permissions": perms,
        "installed": is_installed,
    })
}

/// Build the palette object the TUI reads, with defaults for absent fields so
/// the file is always complete.
fn theme_to_palette(t: &Theme) -> Value {
    // Defaults mirror tui/styles.go so an incomplete theme still renders sanely.
    // Only accept strict #RRGGBB; an untrusted plugin color must never carry an
    // escape sequence through to the terminal.
    let pick = |o: &Option<String>, def: &str| match o {
        Some(v) => clean_hex(v, def),
        None => def.to_string(),
    };
    json!({
        "magenta": pick(&t.magenta, "#EE00FF"),
        "pink":    pick(&t.pink,    "#FF007B"),
        "dark":    pick(&t.dark,    "#17191D"),
        "white":   pick(&t.white,   "#FFFFFF"),
        "border":  pick(&t.border,  "#3A2E3F"),
        "muted":   pick(&t.muted,   "#8A8D93"),
        "green":   pick(&t.green,   "#2ECC71"),
        "yellow":  pick(&t.yellow,  "#F1C40F"),
        "red":     pick(&t.red,     "#E74C3C"),
    })
}

/// True if version `a` is strictly newer than `b` (dotted numeric compare,
/// non-numeric segments compared lexically as a fallback).
pub fn is_newer(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<i64> {
        s.split(|c| c == '.' || c == '+' || c == '-')
            .map(|p| p.parse::<i64>().unwrap_or(-1))
            .collect()
    };
    let (va, vb) = (parse(a), parse(b));
    for i in 0..va.len().max(vb.len()) {
        let x = va.get(i).copied().unwrap_or(0);
        let y = vb.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}

/// Strip terminal-dangerous bytes from a STORE-CONTROLLED display string before it
/// crosses to the TUI. The Go TUI renders these via lipgloss, which does not strip
/// embedded ANSI/OSC escapes (and width-based truncation treats them as zero-width,
/// so they survive). A malicious submission could otherwise smuggle e.g. an OSC 52
/// clipboard-write or screen-clear sequence that fires for anyone who merely opens
/// the plugin store. We drop C0 controls (incl. ESC 0x1B), DEL, and C1 (0x80-0x9F)
/// and bound the length.
fn clean_display(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| {
            let u = *c as u32;
            !(u < 0x20 || u == 0x7f || (0x80..=0x9f).contains(&u))
        })
        .take(max)
        .collect()
}

/// Accept only a strict `#RRGGBB` hex color; anything else (incl. escape payloads)
/// falls back to the provided default. Theme colors come from untrusted plugins and
/// are forwarded to the TUI verbatim otherwise.
fn clean_hex(s: &str, def: &str) -> String {
    let ok = s.len() == 7
        && s.as_bytes()[0] == b'#'
        && s.as_bytes()[1..].iter().all(|b| b.is_ascii_hexdigit());
    if ok {
        s.to_string()
    } else {
        def.to_string()
    }
}

/// Keep a plugin name to a safe path segment ([a-z0-9._-]); never traverses.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches(['.', '-', '_'])
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_and_forbidden_permissions() {
        assert!(validate_permissions(&["tui.theme".into(), "wallet.read.balance".into()]).is_ok());
        assert!(validate_permissions(&["wallet.sign".into()]).is_err());
        assert!(validate_permissions(&["wallet.read.privatekey".into()]).is_err());
        assert!(validate_permissions(&["wallet.read.seed".into()]).is_err());
        assert!(validate_permissions(&["wallet.core".into()]).is_err());
        assert!(validate_permissions(&["notify.bypass".into()]).is_err());
        assert!(validate_permissions(&["ui.official".into()]).is_err());
        // unknown wallet permission is rejected even though not in the explicit list
        assert!(validate_permissions(&["wallet.read.everything".into()]).is_err());
        // unknown non-wallet permission is rejected
        assert!(validate_permissions(&["filesystem.write".into()]).is_err());
    }

    #[test]
    fn version_compare() {
        assert!(is_newer("1.1.0", "1.0.0"));
        assert!(is_newer("2.0.0", "1.9.9"));
        assert!(is_newer("1.0.1", "1.0.0"));
        assert!(!is_newer("1.0.0", "1.0.0"));
        assert!(!is_newer("1.0.0", "1.0.1"));
    }

    #[test]
    fn sanitize_is_safe() {
        assert_eq!(sanitize("pastel-theme"), "pastel-theme");
        assert_eq!(sanitize("../../etc/passwd"), "etc-passwd");
        assert_eq!(sanitize("Foo Bar"), "foo-bar");
    }

    #[test]
    fn sanitize_can_be_empty_for_pathological_names() {
        // These must sanitize to "" so plugin_dir() rejects them — otherwise
        // plugin_dir would resolve to the plugins ROOT and a later remove_dir_all
        // would wipe everything.
        for n in ["", "...", "---", "///", "___", ".-_"] {
            assert!(sanitize(n).is_empty(), "{n:?} must sanitize to empty");
        }
    }

    #[test]
    fn clean_display_strips_escapes() {
        // ESC, OSC payloads, C1 and DEL must be removed; printable text survives.
        let evil = "ok\x1b]52;c;BASE64\x07\u{9b}2J\x7fend";
        let cleaned = clean_display(evil, 1000);
        assert!(!cleaned.contains('\x1b'));
        assert!(!cleaned.contains('\x07'));
        assert!(!cleaned.contains('\u{9b}'));
        assert!(!cleaned.contains('\x7f'));
        assert_eq!(cleaned, "ok]52;c;BASE642Jend");
        assert_eq!(clean_display("abcdef", 3), "abc"); // length bound
    }

    #[test]
    fn clean_hex_accepts_only_strict_colors() {
        assert_eq!(clean_hex("#EE00FF", "#000000"), "#EE00FF");
        assert_eq!(clean_hex("#abc", "#000000"), "#000000"); // too short
        assert_eq!(clean_hex("#GG00FF", "#000000"), "#000000"); // non-hex
        assert_eq!(clean_hex("#EE00FF\x1b[2J", "#000000"), "#000000"); // escape payload
        assert_eq!(clean_hex("red", "#000000"), "#000000");
    }
}
