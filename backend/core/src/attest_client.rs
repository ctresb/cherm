//! Pre-auth attestation client (ATTESTATION.md).
//!
//! `check_server` opens a throwaway TCP connection (no auth), sends an
//! `AttestRequest` with a fresh 32-byte nonce, reads the `AttestResponse`,
//! verifies it against the pinned official trust set, and returns the verdict.
//! The probe connection is closed when the returned future completes (the
//! `TcpStream` is dropped).

use anyhow::{anyhow, Result};
use cherm_attest::{official, verify, Attestation, Tier, Verdict};
use cherm_proto::{read_msg, write_msg, ClientMsg, ServerMsg};
use rand::{rngs::OsRng, RngCore};
use tokio::net::TcpStream;

use crate::now_millis;

/// The result of attesting a server.
pub struct AttestOutcome {
    pub verdict: Verdict,
    pub tier: Tier,
    pub reason: String,
    pub build_hash: String,
    pub fingerprint: String,
    /// Operator-supplied public metadata (from `GetServerInfo`).
    pub server_name: String,
    pub repo_url: String,
    pub description: String,
}

/// Lowercase wire string for a verdict (matches the cached index + TUI).
pub fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Green => "green",
        Verdict::Yellow => "yellow",
        Verdict::Red => "red",
    }
}

/// Lowercase wire string for a tier.
pub fn tier_str(t: Tier) -> &'static str {
    match t {
        Tier::Unsigned => "unsigned",
        Tier::Software => "software",
        Tier::Tee => "tee",
    }
}

/// Connect (pre-auth), attest, verify, and return the verdict. Closes the probe.
pub async fn check_server(addr: &str) -> Result<AttestOutcome> {
    // 32 random bytes, base64 — the freshness nonce bound into the attestation.
    let mut nonce_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = cherm_crypto::b64_encode(&nonce_bytes);

    let mut stream = TcpStream::connect(addr).await?;

    // Announce our build first (so a server with an official-client policy can
    // still serve metadata/attestation pre-auth), then ask for public metadata.
    write_msg(
        &mut stream,
        &ClientMsg::ClientHello {
            build_hash: cherm_attest::build_hash(),
            client_version: "0.1.0+dev".to_string(),
        },
    )
    .await?;
    let _: ServerMsg = read_msg(&mut stream).await?; // Ok

    write_msg(&mut stream, &ClientMsg::GetServerInfo).await?;
    let (server_name, repo_url, description) = match read_msg::<_, ServerMsg>(&mut stream).await? {
        ServerMsg::ServerInfo {
            name,
            repo_url,
            description,
            ..
        } => (name, repo_url, description),
        // A server that doesn't implement metadata just leaves these blank.
        _ => (String::new(), String::new(), String::new()),
    };

    write_msg(
        &mut stream,
        &ClientMsg::AttestRequest {
            nonce: nonce.clone(),
        },
    )
    .await?;

    let resp: ServerMsg = read_msg(&mut stream).await?;
    let attestation = match resp {
        ServerMsg::AttestResponse { attestation } => attestation,
        ServerMsg::Error { code, message } => return Err(anyhow!("{code}: {message}")),
        other => return Err(anyhow!("unexpected attestation reply: {other:?}")),
    };

    let att: Attestation = serde_json::from_value(attestation)?;
    let r = verify(&att, &nonce, now_millis(), &official::pinned());
    Ok(AttestOutcome {
        verdict: r.verdict,
        tier: r.tier,
        reason: r.reason,
        build_hash: r.build_hash,
        fingerprint: r.fingerprint,
        server_name,
        repo_url,
        description,
    })
    // `stream` drops here, closing the probe connection.
}
