package main

import (
	"os"
	"os/exec"
	"runtime"

	"github.com/charmbracelet/lipgloss"
)

// Small helpers shared across the TUI.

// validUsername mirrors cherm_proto::valid_username: 1..=16 chars, ASCII
// letters and digits only. Validation is purely local UX; the core/server are
// the real authority.
func validUsername(name string) bool {
	if len(name) == 0 || len(name) > 16 {
		return false
	}
	for _, r := range name {
		isDigit := r >= '0' && r <= '9'
		isLower := r >= 'a' && r <= 'z'
		isUpper := r >= 'A' && r <= 'Z'
		if !(isDigit || isLower || isUpper) {
			return false
		}
	}
	return true
}

// envServer returns the server address override from CHERM_SERVER, if set.
func envServer() string {
	return os.Getenv("CHERM_SERVER")
}

// envDocs returns the docs URL override from CHERM_DOCS, if set.
func envDocs() string {
	return os.Getenv("CHERM_DOCS")
}

// openBrowser opens url in the user's default browser, cross-platform. It
// returns once the launcher is started (it does not wait for the browser).
func openBrowser(url string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{url}
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		name, args = "xdg-open", []string{url}
	}
	return exec.Command(name, args...).Start()
}

// clampMin returns v, but never below lo.
func clampMin(v, lo int) int {
	if v < lo {
		return lo
	}
	return v
}

// truncate shortens s to fit within w display columns, adding an ellipsis when
// it has to cut. Width is measured the way lipgloss measures it.
func truncate(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	if w == 1 {
		return "…"
	}
	// Trim runes until it fits with room for the ellipsis.
	runes := []rune(s)
	for len(runes) > 0 && lipgloss.Width(string(runes))+1 > w {
		runes = runes[:len(runes)-1]
	}
	return string(runes) + "…"
}
