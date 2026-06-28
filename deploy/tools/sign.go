// sign produces detached Ed25519 signatures over release artifacts. The client
// self-updater (tui/update.go) verifies these with the release public key
// EMBEDDED in the client, so a compromised download origin cannot forge an
// update.
//
//	go run deploy/tools/sign.go <file> [<file> ...]
//
// The signing secret is the project release key. By default it is the DEV seed
// (public in the repo — proves the mechanism, not a production trust root);
// override with CHERM_RELEASE_SECRET_B64 for a real release. The matching public
// key must be embedded as releasePublicKeyB64 in tui/update.go — this tool prints
// the derived public key so the two can be checked.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
)

// devReleaseSeedB64 mirrors cherm_attest::official::DEV_RELEASE_SECRET_B64.
const devReleaseSeedB64 = "IwAL8LHaDW6SOrgkBVl0FUUuYXsZgcGJJb4PLIf7Fss="

func main() {
	seedB64 := os.Getenv("CHERM_RELEASE_SECRET_B64")
	if seedB64 == "" {
		seedB64 = devReleaseSeedB64
	}
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintln(os.Stderr, "error: release secret must be base64 of 32 bytes")
		os.Exit(1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	fmt.Fprintf(os.Stderr, "signing with release public key: %s\n", pub)

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sign <file> [<file> ...]")
		os.Exit(1)
	}
	for _, f := range os.Args[1:] {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", f, err)
			os.Exit(1)
		}
		sig := ed25519.Sign(priv, data)
		out := base64.StdEncoding.EncodeToString(sig)
		if err := os.WriteFile(f+".sig", []byte(out), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s.sig: %v\n", f, err)
			os.Exit(1)
		}
		fmt.Printf("  signed %s\n", f)
	}
}
