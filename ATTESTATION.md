# cherm.chat server attestation

A relay never sees plaintext, but you still have to trust the *operator* not to
run malware that does traffic analysis, blocks people, or lies about who's on
the network. Attestation lets a client check **what code a server runs** before
connecting, and show an honest verdict.

## The hard truth (why three tiers exist)

**Software cannot prove its own integrity.** A binary that computes and reports
a hash of itself can be patched to report any hash — the operator controls the
process. So a pure-software "server hash" is a *deterrent and an accountability
tool*, not a guarantee. The only way to make the running-code measurement
**unforgeable** is a hardware root of trust (a TEE), where the measurement and
signature are produced by silicon/firmware outside the operator's control. Even
then you trade operator-trust for **vendor-trust** (e.g. AWS for Nitro).

cherm is honest about this with three tiers:

| tier | what it proves | UI |
|---|---|---|
| **unsigned** | nothing — operator-controlled, unverified | 🔴 red |
| **software** | this build hash is a genuine, officially-released hash, signed by the project release key. Does **NOT** prove the server actually runs it (replayable). | 🟡 yellow |
| **tee** | hardware attests the running code's measurement equals the official one, and binds a fresh nonce + the server's instance key. Unforgeable modulo trusting the TEE vendor. | 🟢 green |

The page **https://cherm.chat/signatures** explains the three levels to users
(linked from the yellow "learn more" and surfaced in the verdict screen).

## Verdict logic (client)

Given an `Attestation` answering a fresh client nonce, and the pinned official
values baked into the client (`cherm-attest::official`):

```
tee   + quote valid + PCR0 == official measurement + nonce bound   -> GREEN  "safe to connect"
software + release_sig valid under pinned key + build_hash == official -> YELLOW "software signature only"
anything else (unsigned, bad signature, hash/measurement mismatch)  -> RED    "does not match the official public codebase"
```

- **GREEN**: buttons `Cancel` · `Connect` (then create a username).
- **YELLOW**: text "this server has only a software signature" + a *learn more*
  link → `/signatures`; buttons `Cancel` · `Connect`.
- **RED**: text "this server does not match the official public codebase — it
  might be dangerous", with **public codebase** highlighted/clickable →
  `https://github.com/cherm-chat/cherm`; buttons `Cancel` · `Connect anyway`,
  where **Connect anyway** is disabled for a **10-second countdown**.

## Wire protocol (pre-auth, before registering a username)

Client opens the connection and, before anything else, runs the attestation
handshake:

```
C -> AttestRequest { nonce }                       // nonce = 32 random bytes, base64
S -> AttestResponse {
       tier: "unsigned" | "software" | "tee",
       nonce,                                       // echoed
       server_unix_ms,
       build_hash,            // hex, blake3 of the server's build artifact
       build_hash_alg: "blake3",
       release_version,       // "x.y.z+gitsha"
       release_key_id,        // base64 8 bytes, selects which pinned release key
       release_sig,           // minisign signature over "cherm-release\n<version>\n<build_hash>"
       instance_pub,          // base64 ed25519 instance key (per-server)
       instance_sig,          // base64 ed25519 sig over (nonce || build_hash || server_unix_ms)
       tee_quote              // base64 AWS Nitro COSE_Sign1 doc (present iff tier=="tee")
     }
```

- `instance_sig` proves liveness/anti-replay of *this* server's instance key,
  but the instance key is **not** tied to the code in the software tier — that
  is exactly why software is a deterrent. In the **tee** tier the Nitro quote's
  `user_data` binds `instance_pub` to the measured enclave, upgrading it to a
  real guarantee. The Nitro doc's own `nonce` field carries the client nonce for
  freshness.

## TEE tier: AWS Nitro Enclaves verification (pure-Rust client verifier)

The verifier runs on **any** device (no AWS deps); only *producing* a quote
needs an EC2 Nitro enclave. Steps (`cherm-attest::nitro`):

1. CBOR/COSE parse the `tee_quote` as a tagged `COSE_Sign1` (`coset`), require
   alg `ES384` (-35).
2. CBOR-decode the payload (`ciborium`) → attestation document: `module_id`,
   `pcrs` (PCR0 = enclave image measurement), `certificate` (leaf, DER),
   `cabundle` (intermediates), `public_key`/`user_data`/`nonce`.
3. Validate the cert chain `leaf -> cabundle -> ` **pinned AWS Nitro Root-G1**
   (DER embedded; SHA-256 fingerprint
   `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`),
   checking validity periods.
4. Verify the COSE signature with the **leaf** cert's P-384 key (`p384` ES384)
   over the reconstructed `Sig_structure`.
5. Check `pcrs[0] == official.NITRO_PCR0`, `nonce == client nonce`,
   `user_data` binds `instance_pub`, and `timestamp` is fresh.

A real positive quote can't be generated on a non-Nitro dev box, so the
verifier is unit-tested for parsing + every negative path (bad sig, wrong root,
wrong PCR0, stale nonce); end-to-end GREEN is validated on the enclave
deployment. The official server image is a reproducible `.eif`; its PCR0 is
published so anyone can rebuild and confirm `official.NITRO_PCR0`.

## Software tier honesty

`release_sig` is a **static** project signature over `version + build_hash`,
created once at release and shipped with the build; the server just relays it.
It proves "`build_hash` is a real official release". It is **not** bound to the
client nonce (the operator doesn't hold the project key), so a malicious
operator can replay the official hash + signature while running modified code.
That's the residual gap the TEE tier closes. The official hash + release public
keys are pinned in the client and published in a transparency log so a silent
swap of the "official" value is detectable.
