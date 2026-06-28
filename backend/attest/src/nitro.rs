//! AWS Nitro Enclaves attestation-document verification (pure Rust).
//!
//! The verifier runs on any device; only *producing* a quote needs an EC2 Nitro
//! enclave. See ATTESTATION.md for the full checklist. Steps:
//!   1. parse the tagged COSE_Sign1 quote;
//!   2. CBOR-decode the attestation document payload;
//!   3. validate the cert chain leaf -> cabundle -> pinned AWS root (sigs +
//!      validity), pinning the root by its public key;
//!   4. verify the COSE ES384 signature with the leaf's P-384 key;
//!   5. check PCR0 == official, nonce == client nonce, timestamp fresh, and
//!      user_data binds the server's instance key.

use anyhow::{anyhow, bail, Result};
use coset::{CoseSign1, TaggedCborSerializable};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

/// Max clock skew / document age accepted (5 minutes).
const MAX_AGE_MS: i64 = 5 * 60 * 1000;

/// The Nitro attestation document (the COSE payload).
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationDoc {
    pub module_id: String,
    pub digest: String,
    pub timestamp: u64,
    pub pcrs: BTreeMap<u8, ByteBuf>,
    pub certificate: ByteBuf,
    pub cabundle: Vec<ByteBuf>,
    #[serde(default)]
    pub public_key: Option<ByteBuf>,
    #[serde(default)]
    pub user_data: Option<ByteBuf>,
    #[serde(default)]
    pub nonce: Option<ByteBuf>,
}

/// Claims returned after a successful verification.
#[derive(Debug)]
pub struct NitroClaims {
    pub pcr0_hex: String,
    pub module_id: String,
    pub user_data: Option<Vec<u8>>,
}

/// Verify a Nitro quote end-to-end.
pub fn verify(
    quote: &[u8],
    expected_pcr0_hex: Option<&str>,
    expected_nonce: &[u8],
    now_ms: i64,
    roots: &[Vec<u8>],
    expect_user_data: Option<&[u8]>,
) -> Result<NitroClaims> {
    let cose = CoseSign1::from_tagged_slice(quote).map_err(|e| anyhow!("cose parse: {e:?}"))?;
    let payload = cose
        .payload
        .as_ref()
        .ok_or_else(|| anyhow!("attestation has no payload"))?;
    let doc = parse_doc(payload)?;

    // Cert chain: leaf (doc.certificate) preceded by cabundle (root-first).
    let leaf_key = verify_chain(&doc.certificate, &doc.cabundle, roots, now_ms)?;

    // COSE ES384 signature over the Sig_structure, by the leaf key.
    verify_cose_with_key(&cose, &leaf_key)?;

    // Freshness.
    let ts = doc.timestamp as i64;
    if (now_ms - ts).abs() > MAX_AGE_MS {
        bail!("attestation timestamp not fresh (age {} ms)", now_ms - ts);
    }

    // Nonce binding (anti-replay).
    match &doc.nonce {
        Some(n) if n.as_slice() == expected_nonce => {}
        _ => bail!("attestation nonce does not match the client nonce"),
    }

    // PCR0 == official measurement.
    let pcr0 = doc
        .pcrs
        .get(&0)
        .ok_or_else(|| anyhow!("no PCR0 in attestation"))?;
    let pcr0_hex = hex::encode(pcr0.as_slice());
    if let Some(expected) = expected_pcr0_hex {
        if !expected.eq_ignore_ascii_case(&pcr0_hex) {
            bail!("PCR0 does not match the official enclave measurement");
        }
    }

    // Bind the server instance key.
    if let Some(want) = expect_user_data {
        match &doc.user_data {
            Some(u) if u.as_slice() == want => {}
            _ => bail!("attestation user_data does not bind the server instance key"),
        }
    }

    Ok(NitroClaims {
        pcr0_hex,
        module_id: doc.module_id,
        user_data: doc.user_data.map(|b| b.into_vec()),
    })
}

/// CBOR-decode the attestation document payload.
pub fn parse_doc(payload: &[u8]) -> Result<AttestationDoc> {
    ciborium::from_reader(payload).map_err(|e| anyhow!("cbor decode: {e}"))
}

/// Verify the COSE_Sign1 ES384 signature with a P-384 public key.
pub fn verify_cose_with_key(cose: &CoseSign1, key: &VerifyingKey) -> Result<()> {
    let tbs = cose.tbs_data(&[]);
    let sig = Signature::from_slice(&cose.signature).map_err(|e| anyhow!("bad signature: {e}"))?;
    key.verify(&tbs, &sig)
        .map_err(|e| anyhow!("cose signature invalid: {e}"))
}

/// Validate the certificate chain and return the leaf's P-384 public key.
fn verify_chain(
    leaf_der: &[u8],
    cabundle: &[ByteBuf],
    roots: &[Vec<u8>],
    now_ms: i64,
) -> Result<VerifyingKey> {
    if cabundle.is_empty() {
        bail!("empty cabundle");
    }
    if roots.is_empty() {
        bail!("no pinned roots configured");
    }

    // Full path, root-first: [cabundle..., leaf].
    let mut path: Vec<Certificate> = Vec::with_capacity(cabundle.len() + 1);
    for c in cabundle {
        path.push(Certificate::from_der(c).map_err(|e| anyhow!("cabundle cert: {e}"))?);
    }
    path.push(Certificate::from_der(leaf_der).map_err(|e| anyhow!("leaf cert: {e}"))?);

    // Pin the chain root to a trusted root by public key.
    let root_spki = spki_bytes(&path[0])?;
    let trusted = roots.iter().any(|r| {
        Certificate::from_der(r)
            .ok()
            .and_then(|c| spki_bytes(&c).ok())
            .map(|s| s == root_spki)
            .unwrap_or(false)
    });
    if !trusted {
        bail!("attestation root is not the pinned AWS Nitro root");
    }

    // Validity windows.
    for cert in &path {
        check_validity(cert, now_ms)?;
    }
    // Each cert (after the root) must be signed by its predecessor.
    for i in 1..path.len() {
        let issuer_key = p384_from_cert(&path[i - 1])?;
        verify_cert_signed_by(&path[i], &issuer_key)?;
    }

    p384_from_cert(path.last().unwrap())
}

fn verify_cert_signed_by(child: &Certificate, issuer_key: &VerifyingKey) -> Result<()> {
    let tbs = child
        .tbs_certificate
        .to_der()
        .map_err(|e| anyhow!("encode tbs: {e}"))?;
    let sig_bytes = child
        .signature
        .as_bytes()
        .ok_or_else(|| anyhow!("no signature bits"))?;
    let sig = Signature::from_der(sig_bytes).map_err(|e| anyhow!("cert sig parse: {e}"))?;
    issuer_key
        .verify(&tbs, &sig)
        .map_err(|e| anyhow!("cert chain signature invalid: {e}"))
}

fn spki_bytes(cert: &Certificate) -> Result<Vec<u8>> {
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| anyhow!("spki: {e}"))
}

fn p384_from_cert(cert: &Certificate) -> Result<VerifyingKey> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| anyhow!("no spki bits"))?;
    VerifyingKey::from_sec1_bytes(bytes).map_err(|e| anyhow!("p384 key: {e}"))
}

fn check_validity(cert: &Certificate, now_ms: i64) -> Result<()> {
    let v = &cert.tbs_certificate.validity;
    let nb = v.not_before.to_unix_duration().as_millis() as i64;
    let na = v.not_after.to_unix_duration().as_millis() as i64;
    if now_ms < nb {
        bail!("certificate not yet valid");
    }
    if now_ms > na {
        bail!("certificate expired");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::{iana, CoseSign1Builder, HeaderBuilder};
    use p384::ecdsa::{signature::Signer, SigningKey};

    fn sample_doc(nonce: &[u8], pcr0: &[u8]) -> Vec<u8> {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0u8, ByteBuf::from(pcr0.to_vec()));
        let doc = AttestationDoc {
            module_id: "i-test".into(),
            digest: "SHA384".into(),
            timestamp: 1_700_000_000_000,
            pcrs,
            certificate: ByteBuf::from(vec![1, 2, 3]),
            cabundle: vec![ByteBuf::from(vec![4, 5, 6])],
            public_key: None,
            user_data: Some(ByteBuf::from(b"instance-key".to_vec())),
            nonce: Some(ByteBuf::from(nonce.to_vec())),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&doc, &mut buf).unwrap();
        buf
    }

    fn cose_signed(payload: Vec<u8>, sk: &SigningKey) -> Vec<u8> {
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES384)
            .build();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(&[], |tbs| {
                let sig: Signature = sk.sign(tbs);
                sig.to_bytes().to_vec()
            })
            .build();
        sign1.to_tagged_vec().unwrap()
    }

    #[test]
    fn cose_sign_and_verify_roundtrip() {
        let sk = SigningKey::random(&mut rand::rngs::OsRng);
        let vk = *sk.verifying_key();
        let payload = sample_doc(b"nonce123", &[7u8; 48]);
        let quote = cose_signed(payload.clone(), &sk);

        let cose = CoseSign1::from_tagged_slice(&quote).unwrap();
        assert!(verify_cose_with_key(&cose, &vk).is_ok());

        // wrong key rejected
        let other = *SigningKey::random(&mut rand::rngs::OsRng).verifying_key();
        assert!(verify_cose_with_key(&cose, &other).is_err());
    }

    #[test]
    fn doc_parse_extracts_fields() {
        let sk = SigningKey::random(&mut rand::rngs::OsRng);
        let payload = sample_doc(b"the-nonce", &[9u8; 48]);
        let quote = cose_signed(payload, &sk);
        let cose = CoseSign1::from_tagged_slice(&quote).unwrap();
        let doc = parse_doc(cose.payload.as_ref().unwrap()).unwrap();
        assert_eq!(doc.nonce.as_ref().unwrap().as_slice(), b"the-nonce");
        assert_eq!(doc.pcrs.get(&0).unwrap().len(), 48);
        assert_eq!(doc.user_data.as_ref().unwrap().as_slice(), b"instance-key");
    }

    #[test]
    fn garbage_quote_is_rejected() {
        let err = verify(&[0, 1, 2, 3], None, b"n", 1_700_000_000_000, &[vec![0u8]], None);
        assert!(err.is_err());
    }

    #[test]
    fn tampered_payload_breaks_signature() {
        let sk = SigningKey::random(&mut rand::rngs::OsRng);
        let vk = *sk.verifying_key();
        let payload = sample_doc(b"n", &[1u8; 48]);
        let mut quote = cose_signed(payload, &sk);
        let n = quote.len();
        quote[n - 5] ^= 0xff; // flip a signature byte
        let cose = CoseSign1::from_tagged_slice(&quote).unwrap();
        assert!(verify_cose_with_key(&cose, &vk).is_err());
    }
}
