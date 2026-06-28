package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Layout chrome styles. Kept separate from message-bubble rendering (render.go)
// so the presentation of the shell can evolve independently of the protocol's
// fixed message format. Message bubbles stay white (premium-gated, PROTOCOL.md
// section 6); the palette below only dresses the surrounding UI.

// Palette (user-provided): magenta -> pink accent, near-black base, white text.
const (
	hexMagenta = "#EE00FF"
	hexPink    = "#FF007B"
	hexDark    = "#17191D"
	hexWhite   = "#FFFFFF"
)

var (
	cMagenta = lipgloss.Color(hexMagenta)
	cPink    = lipgloss.Color(hexPink)
	cDark    = lipgloss.Color(hexDark)
	cWhite   = lipgloss.Color(hexWhite)
	// cBorder is a dim, magenta-tinted border for unfocused panes; cMuted is
	// low-emphasis text.
	cBorder = lipgloss.Color("#3A2E3F")
	cMuted  = lipgloss.Color("#8A8D93")

	// verdict colors (attestation traffic-light: green tee / yellow software /
	// red). Semantic only — they dress the attestation UI and never the chat
	// bubbles, which stay white per PROTOCOL.md section 6.
	cGreen  = lipgloss.Color("#2ECC71")
	cYellow = lipgloss.Color("#F1C40F")
	cRed    = lipgloss.Color("#E74C3C")

	// colorAccent is the primary accent (focused borders, selections).
	colorAccent = cMagenta

	// titleStyle heads the sidebar / panels.
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(cMagenta)

	// sidebar item styles.
	itemStyle     = lipgloss.NewStyle().Foreground(cWhite)
	selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(cDark).Background(cMagenta)
	activityStyle = lipgloss.NewStyle().Foreground(cPink).Bold(true)

	// footer + transient status line.
	footerStyle = lipgloss.NewStyle().Foreground(cMuted)
	statusStyle = lipgloss.NewStyle().Foreground(cMagenta)
	errStyle    = lipgloss.NewStyle().Foreground(cPink)

	// header + menu styles.
	badgeOn   = lipgloss.NewStyle().Foreground(cDark).Background(cMagenta).Bold(true).Padding(0, 1)
	badgeOff  = lipgloss.NewStyle().Foreground(cWhite).Background(cBorder).Padding(0, 1)
	menuKey   = lipgloss.NewStyle().Foreground(cMuted)
	menuLabel = lipgloss.NewStyle().Foreground(cWhite)
	menuSel   = lipgloss.NewStyle().Foreground(cPink).Bold(true)

	// attestation verdict badges + body text.
	badgeGreen  = lipgloss.NewStyle().Foreground(cDark).Background(cGreen).Bold(true).Padding(0, 1)
	badgeYellow = lipgloss.NewStyle().Foreground(cDark).Background(cYellow).Bold(true).Padding(0, 1)
	badgeRed    = lipgloss.NewStyle().Foreground(cWhite).Background(cRed).Bold(true).Padding(0, 1)
	greenText   = lipgloss.NewStyle().Foreground(cGreen).Bold(true)
	yellowText  = lipgloss.NewStyle().Foreground(cYellow).Bold(true)
	redText     = lipgloss.NewStyle().Foreground(cRed).Bold(true)

	// linkStyle highlights a clickable URL (the yellow "learn more" and the red
	// "public codebase").
	linkStyle = lipgloss.NewStyle().Foreground(cMagenta).Underline(true).Bold(true)
)

// boxStyle returns a rounded-border box whose border color reflects focus.
func boxStyle(focused bool) lipgloss.Style {
	c := cBorder
	if focused {
		c = cMagenta
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(c)
}

// panelStyle is the rounded, accented container used for the onboarding, menu
// and help screens.
func panelStyle() lipgloss.Style {
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(cMagenta).
		Padding(1, 3)
}

// gradientText colors each rune of s along a linear interpolation from the
// hex color `from` to the hex color `to` (used for accent details like the
// logo, per the requested magenta -> pink gradient).
func gradientText(s, from, to string, bold bool) string {
	runes := []rune(s)
	n := len(runes)
	if n == 0 {
		return s
	}
	fr, fg, fb := hexToRGB(from)
	tr, tg, tb := hexToRGB(to)
	var b strings.Builder
	for i, r := range runes {
		t := 0.0
		if n > 1 {
			t = float64(i) / float64(n-1)
		}
		col := fmt.Sprintf("#%02X%02X%02X",
			lerp(fr, tr, t), lerp(fg, tg, t), lerp(fb, tb, t))
		st := lipgloss.NewStyle().Foreground(lipgloss.Color(col))
		if bold {
			st = st.Bold(true)
		}
		b.WriteString(st.Render(string(r)))
	}
	return b.String()
}

func hexToRGB(h string) (int, int, int) {
	h = strings.TrimPrefix(h, "#")
	var r, g, b int
	fmt.Sscanf(h, "%02x%02x%02x", &r, &g, &b)
	return r, g, b
}

func lerp(a, b int, t float64) int {
	return int(float64(a) + (float64(b)-float64(a))*t + 0.5)
}
