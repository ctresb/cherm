package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// devReleaseSeedB64 mirrors the signing seed in deploy/tools/sign.go (the public
// dev key; a real release uses a secret seed). Its public half must equal the
// key embedded in the client (releasePublicKeyB64).
const devReleaseSeedB64 = "IwAL8LHaDW6SOrgkBVl0FUUuYXsZgcGJJb4PLIf7Fss="

func devSign(t *testing.T, data []byte) string {
	seed, err := base64.StdEncoding.DecodeString(devReleaseSeedB64)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))
}

func TestVerifyReleaseSig(t *testing.T) {
	// The embedded public key must match the dev signing key.
	seed, _ := base64.StdEncoding.DecodeString(devReleaseSeedB64)
	pub := base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if pub != releasePublicKeyB64 {
		t.Fatalf("embedded key %q != dev signing key %q", releasePublicKeyB64, pub)
	}

	artifact := []byte("pretend this is cherm-client-macos-arm64.tar.gz")
	good := devSign(t, artifact)

	// A valid signature over the exact bytes verifies.
	if err := verifyReleaseSig(artifact, good); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}
	// A tampered artifact (attacker swaps the binary) must be rejected even with
	// the original signature.
	tampered := append([]byte{}, artifact...)
	tampered[0] ^= 0xff
	if err := verifyReleaseSig(tampered, good); err == nil {
		t.Error("tampered artifact accepted — signature check is ineffective")
	}
	// A signature from a different (attacker) key must be rejected.
	otherSeed := make([]byte, ed25519.SeedSize)
	otherSeed[0] = 7
	otherPriv := ed25519.NewKeyFromSeed(otherSeed)
	forged := base64.StdEncoding.EncodeToString(ed25519.Sign(otherPriv, artifact))
	if err := verifyReleaseSig(artifact, forged); err == nil {
		t.Error("signature from a non-release key accepted")
	}
	// Garbage / empty signatures are rejected.
	if err := verifyReleaseSig(artifact, "not-base64!!"); err == nil {
		t.Error("malformed signature accepted")
	}
	if err := verifyReleaseSig(artifact, ""); err == nil {
		t.Error("empty signature accepted")
	}
}

func TestIsNewerVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.2.0", "0.1.0", true},
		{"0.1.1", "0.1.0", true},
		{"1.0.0", "0.9.9", true},
		{"0.1.0", "0.1.0", false},
		{"0.1.0", "0.2.0", false},
		{"0.1.0", "0.1.0+dev", false}, // +dev suffix ignored
	}
	for _, c := range cases {
		if got := isNewerVersion(c.a, c.b); got != c.want {
			t.Errorf("isNewerVersion(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}
