//! Client update detection (install_specification §8).
//!
//! The official client checks `cherm.chat` for a newer release and *notifies*
//! the user — it never installs silently. The release manifest is machine-
//! readable JSON published next to the installers:
//!
//! ```json
//! { "client": { "version": "0.1.0", "notes_url": "...", "url": "...",
//!               "channel": "stable" } }
//! ```
//!
//! We compare the advertised version to our own and emit
//! `client_update_available` when it is newer. The TUI then offers
//! Update / Ignore / Details (install_specification §8.2). Updating itself runs
//! the official installer, which verifies checksums and preserves wallet/config.

use anyhow::Result;
use serde::Deserialize;
use serde_json::json;

use crate::ipc::Events;
use crate::plugins::is_newer;

/// Default release-metadata URL. Overridable via `CHERM_UPDATE_URL` for testing.
const DEFAULT_UPDATE_URL: &str = "https://cherm.chat/version.json";

#[derive(Debug, Default, Deserialize)]
struct ReleaseMeta {
    #[serde(default)]
    client: ClientMeta,
}

#[derive(Debug, Default, Deserialize)]
struct ClientMeta {
    #[serde(default)]
    version: String,
    #[serde(default)]
    notes_url: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    channel: String,
}

/// Check `cherm.chat` for a newer client and emit a notification event.
pub async fn check_client_update(current_version: &str, events: &Events) -> Result<()> {
    let url = std::env::var("CHERM_UPDATE_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_UPDATE_URL.to_string());

    let client = reqwest::Client::builder()
        .user_agent(concat!("cherm-core/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_default();

    let meta: ReleaseMeta = match client.get(&url).send().await {
        Ok(r) => r.json().await.unwrap_or_default(),
        Err(e) => {
            events.emit(json!({
                "event": "error", "code": "update_check_failed",
                "message": format!("could not check for updates: {e}")
            }));
            return Ok(());
        }
    };

    // Compare ignoring a local "+dev" suffix so a dev build still gets notified.
    let current = current_version.split('+').next().unwrap_or(current_version);
    if !meta.client.version.is_empty() && is_newer(&meta.client.version, current) {
        events.emit(json!({
            "event": "client_update_available",
            "current": current_version,
            "latest": meta.client.version,
            "notes_url": meta.client.notes_url,
            "url": meta.client.url,
            "channel": meta.client.channel,
        }));
    } else {
        events.emit(json!({
            "event": "info",
            "message": format!("client is up to date (v{current})")
        }));
    }
    Ok(())
}
