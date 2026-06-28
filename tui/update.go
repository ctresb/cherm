package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// releasePublicKeyB64 is the project's Ed25519 release public key, EMBEDDED in
// the client at build time. Update artifacts must carry a detached signature
// (`<artifact>.sig`, base64 Ed25519 over the tarball bytes) made with the
// matching release secret; the client verifies it with THIS key before
// installing. This is the trust anchor — it does not depend on the artifact's
// origin, so a compromised/MITM'd download host (or a hostile CHERM_BASE_URL)
// cannot install a forged binary: it cannot forge a signature.
//
// NOTE (honest scope, same as ATTESTATION.md's software tier): the default value
// is the project DEV release key, whose secret is public in the repo — it proves
// the update mechanism but is not a real production trust root. A real release
// embeds a public key whose secret is held only by the project.
const releasePublicKeyB64 = "rP8FiokGtvgz/SsImR73QCYo8fL5tAbw333dA5tUNJ8="

// verifyReleaseSig checks a detached base64 Ed25519 signature over data against
// the embedded release public key.
func verifyReleaseSig(data []byte, sigB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(releasePublicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid embedded release key")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("malformed release signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		return fmt.Errorf("release signature does not verify against the embedded key")
	}
	return nil
}

// Client self-update (install_specification §8). `cherm --update` checks
// cherm.chat for a newer build and, if found, downloads + verifies (SHA-256) +
// installs it in place — preserving ~/.cherm (wallet/config/plugins). The same
// selfUpdate() powers the in-app "Update now" action on the update banner.

// clientVersion is this client's release version (matches version.json's
// client.version when up to date).
const clientVersion = "0.1.1"

// updateBaseURL is the release origin; override with CHERM_BASE_URL for testing.
func updateBaseURL() string {
	if b := os.Getenv("CHERM_BASE_URL"); b != "" {
		return strings.TrimRight(b, "/")
	}
	return "https://cherm.chat"
}

// updatePlatform returns the artifact platform tag for this machine.
func updatePlatform() (string, error) {
	var os_, arch string
	switch runtime.GOOS {
	case "darwin":
		os_ = "macos"
	case "linux":
		os_ = "linux"
	case "windows":
		os_ = "windows"
	default:
		return "", fmt.Errorf("unsupported OS %s", runtime.GOOS)
	}
	switch runtime.GOARCH {
	case "arm64":
		arch = "arm64"
	case "amd64":
		arch = "x64"
	default:
		return "", fmt.Errorf("unsupported arch %s", runtime.GOARCH)
	}
	return os_ + "-" + arch, nil
}

type releaseMeta struct {
	Client struct {
		Version  string `json:"version"`
		NotesURL string `json:"notes_url"`
	} `json:"client"`
}

func httpGet(url string) ([]byte, error) {
	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s -> HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// latestClientVersion reads cherm.chat/version.json.
func latestClientVersion() (string, error) {
	body, err := httpGet(updateBaseURL() + "/version.json")
	if err != nil {
		return "", err
	}
	var m releaseMeta
	if err := json.Unmarshal(body, &m); err != nil {
		return "", err
	}
	if m.Client.Version == "" {
		return "", fmt.Errorf("no client version in version.json")
	}
	return m.Client.Version, nil
}

// isNewerVersion reports whether a is strictly newer than b (dotted numeric).
func isNewerVersion(a, b string) bool {
	pa, pb := parseVer(a), parseVer(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func parseVer(s string) []int {
	s = strings.SplitN(s, "+", 2)[0]
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' })
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			n = -1
		}
		out = append(out, n)
	}
	return out
}

// selfUpdate downloads the latest client (if newer, or always when force),
// verifies its SHA-256, and replaces cherm + cherm-core next to the running
// binary. Returns the installed version. ~/.cherm is never touched.
func selfUpdate(force bool) (string, error) {
	platform, err := updatePlatform()
	if err != nil {
		return "", err
	}
	latest, err := latestClientVersion()
	if err != nil {
		return "", err
	}
	if !force && !isNewerVersion(latest, clientVersion) {
		return latest, errAlreadyLatest
	}

	base := updateBaseURL()
	artifact := fmt.Sprintf("cherm-client-%s.tar.gz", platform)
	url := fmt.Sprintf("%s/releases/client/%s/%s", base, latest, artifact)

	tarball, err := httpGet(url)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", artifact, err)
	}

	// TRUST ANCHOR: verify the detached Ed25519 signature with the EMBEDDED
	// release key BEFORE doing anything with the artifact. A same-origin hash is
	// not enough (an attacker controlling the origin/TLS swaps both), so the
	// signature — not the hash — gates the install.
	sigB64, err := httpGet(url + ".sig")
	if err != nil {
		return "", fmt.Errorf("fetch release signature: %w (refusing to install unsigned update)", err)
	}
	if err := verifyReleaseSig(tarball, string(sigB64)); err != nil {
		return "", fmt.Errorf("signature verification failed: %w", err)
	}

	// Secondary, non-security integrity check (corruption / truncation): the
	// SHA-256 sidecar, when present, must also match.
	if wantRaw, err := httpGet(url + ".sha256"); err == nil {
		want := strings.Fields(string(wantRaw))
		got := sha256.Sum256(tarball)
		if len(want) == 0 || want[0] != hex.EncodeToString(got[:]) {
			return "", fmt.Errorf("checksum mismatch — refusing to install")
		}
	}

	// Where to install: next to the currently running executable.
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	installDir := filepath.Dir(exe)

	bins, err := extractBinaries(tarball)
	if err != nil {
		return "", err
	}
	for _, name := range []string{"cherm", "cherm-core"} {
		data, ok := bins[name]
		if !ok {
			return "", fmt.Errorf("archive missing %s", name)
		}
		if err := replaceBinary(filepath.Join(installDir, name), data); err != nil {
			return "", fmt.Errorf("install %s: %w", name, err)
		}
	}
	return latest, nil
}

var errAlreadyLatest = fmt.Errorf("already on the latest version")

// extractBinaries pulls cherm + cherm-core out of a .tar.gz into memory.
func extractBinaries(targz []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(strings.NewReader(string(targz)))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		base := filepath.Base(h.Name)
		if base == "cherm" || base == "cherm-core" {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			out[base] = data
		}
	}
	return out, nil
}

// replaceBinary writes data to a temp file in the target's dir, then atomically
// renames it over the target (works even while the binary is running on Unix).
func replaceBinary(target string, data []byte) error {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".cherm-upd-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}
	return os.Rename(tmpName, target)
}

// runUpdateCLI implements `cherm --update [--force]`: checks, downloads,
// verifies, installs, and prints what happened. Returns the process exit code.
func runUpdateCLI(force bool) int {
	fmt.Printf("Cherm Client v%s — checking for updates…\n", clientVersion)
	latest, err := latestClientVersion()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if !force && !isNewerVersion(latest, clientVersion) {
		fmt.Printf("Already on the latest version (v%s).\n", clientVersion)
		return 0
	}
	fmt.Printf("Updating to v%s…\n", latest)
	got, err := selfUpdate(force)
	if err != nil && err != errAlreadyLatest {
		fmt.Fprintf(os.Stderr, "update failed: %v\n", err)
		return 1
	}
	fmt.Printf("Updated to v%s. Your wallet/config/plugins were preserved.\nRun: cherm\n", got)
	return 0
}
