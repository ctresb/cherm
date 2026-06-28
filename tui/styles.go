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
//
// THEMING (architecture_specification §6.1 — "a theme is a plugin"): the palette
// is a RUNTIME value, not a set of constants. It is loaded from the active theme
// plugin's `active-theme.json` at startup and re-applied live when the core emits
// a `theme` event after a theme plugin is installed/removed. Every palette-derived
// style is (re)assigned in applyPalette so a theme change takes effect on the next
// render without a restart. bubbletea serializes Update/View on one goroutine, so
// mutating these package globals from Update (a themeMsg) is safe.

// hex* are the ACTIVE palette hexes (mutated by applyPalette). Defaults mirror
// the original magenta→pink accent on a near-black base.
var (
	hexMagenta = "#EE00FF"
	hexPink    = "#FF007B"
	hexDark    = "#17191D"
	hexWhite   = "#FFFFFF"
)

// Active palette colors (assigned by applyPalette).
var (
	cMagenta lipgloss.Color
	cPink    lipgloss.Color
	cDark    lipgloss.Color
	cWhite   lipgloss.Color
	cBorder  lipgloss.Color
	cMuted   lipgloss.Color
	cGreen   lipgloss.Color
	cYellow  lipgloss.Color
	cRed     lipgloss.Color

	// cOutgoingBg is a subtle, theme-derived background band for the user's own
	// messages, so they read differently from incoming ones (text stays white).
	cOutgoingBg lipgloss.Color

	// colorAccent is the primary accent (focused borders, selections).
	colorAccent lipgloss.Color
)

// Palette-derived styles. Declared bare (zero value) and assigned in
// applyPalette — never initialized at declaration, or they would capture the
// zero-value colors before applyPalette runs.
var (
	titleStyle lipgloss.Style

	itemStyle     lipgloss.Style
	selectedStyle lipgloss.Style
	activityStyle lipgloss.Style

	footerStyle lipgloss.Style
	statusStyle lipgloss.Style
	errStyle    lipgloss.Style

	badgeOn   lipgloss.Style
	badgeOff  lipgloss.Style
	menuKey   lipgloss.Style
	menuLabel lipgloss.Style
	menuSel   lipgloss.Style

	badgeGreen  lipgloss.Style
	badgeYellow lipgloss.Style
	badgeRed    lipgloss.Style
	greenText   lipgloss.Style
	yellowText  lipgloss.Style
	redText     lipgloss.Style

	linkStyle lipgloss.Style

	// system message styles (used by render.go).
	systemPrefixStyle lipgloss.Style
	systemBodyStyle   lipgloss.Style

	// plugin category badges.
	badgeOfficial   lipgloss.Style
	badgeAudited    lipgloss.Style
	badgeUnaudited  lipgloss.Style
	badgeWidgetText lipgloss.Style

	// lockStyle marks the safety-number / secure indicator (bold gold) — used
	// instead of an emoji (the UI uses no emoji).
	lockStyle lipgloss.Style
)

// init applies the active theme (from disk, falling back to the default palette)
// before the first render. Runs after package var initialization, before main.
func init() {
	applyPalette(loadPaletteFromDisk())
}

// applyPalette recomputes every palette-derived color + style from p. Called at
// startup and again on each live `theme` event so theme plugins re-skin the TUI.
func applyPalette(p Palette) {
	hexMagenta, hexPink, hexDark, hexWhite = p.Magenta, p.Pink, p.Dark, p.White

	cMagenta = lipgloss.Color(p.Magenta)
	cPink = lipgloss.Color(p.Pink)
	cDark = lipgloss.Color(p.Dark)
	cWhite = lipgloss.Color(p.White)
	cBorder = lipgloss.Color(p.Border)
	cMuted = lipgloss.Color(p.Muted)
	cGreen = lipgloss.Color(p.Green)
	cYellow = lipgloss.Color(p.Yellow)
	cRed = lipgloss.Color(p.Red)
	colorAccent = cMagenta

	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(cMagenta)

	itemStyle = lipgloss.NewStyle().Foreground(cWhite)
	selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(cDark).Background(cMagenta)
	activityStyle = lipgloss.NewStyle().Foreground(cPink).Bold(true)

	footerStyle = lipgloss.NewStyle().Foreground(cMuted)
	statusStyle = lipgloss.NewStyle().Foreground(cMagenta)
	errStyle = lipgloss.NewStyle().Foreground(cPink)

	badgeOn = lipgloss.NewStyle().Foreground(cDark).Background(cMagenta).Bold(true).Padding(0, 1)
	badgeOff = lipgloss.NewStyle().Foreground(cWhite).Background(cBorder).Padding(0, 1)
	menuKey = lipgloss.NewStyle().Foreground(cMuted)
	menuLabel = lipgloss.NewStyle().Foreground(cWhite)
	menuSel = lipgloss.NewStyle().Foreground(cPink).Bold(true)

	badgeGreen = lipgloss.NewStyle().Foreground(cDark).Background(cGreen).Bold(true).Padding(0, 1)
	badgeYellow = lipgloss.NewStyle().Foreground(cDark).Background(cYellow).Bold(true).Padding(0, 1)
	badgeRed = lipgloss.NewStyle().Foreground(cWhite).Background(cRed).Bold(true).Padding(0, 1)
	greenText = lipgloss.NewStyle().Foreground(cGreen).Bold(true)
	yellowText = lipgloss.NewStyle().Foreground(cYellow).Bold(true)
	redText = lipgloss.NewStyle().Foreground(cRed).Bold(true)

	linkStyle = lipgloss.NewStyle().Foreground(cMagenta).Underline(true).Bold(true)

	systemPrefixStyle = lipgloss.NewStyle().Bold(true).Foreground(cPink)
	systemBodyStyle = lipgloss.NewStyle().Faint(true).Italic(true)

	// Plugin trust badges: official (accent), audited (green), unaudited (red —
	// use-at-your-own-risk must read as a warning).
	badgeOfficial = lipgloss.NewStyle().Foreground(cDark).Background(cMagenta).Bold(true).Padding(0, 1)
	badgeAudited = lipgloss.NewStyle().Foreground(cDark).Background(cGreen).Bold(true).Padding(0, 1)
	badgeUnaudited = lipgloss.NewStyle().Foreground(cWhite).Background(cRed).Bold(true).Padding(0, 1)
	badgeWidgetText = lipgloss.NewStyle().Foreground(cMuted)
	lockStyle = lipgloss.NewStyle().Bold(true).Foreground(cYellow)

	// Subtle outgoing-message band: the base dark nudged toward the accent, so
	// the user's own lines read differently without coloring the (white) text.
	cOutgoingBg = lipgloss.Color(blendHex(p.Dark, p.Magenta, 0.16))
}

// blendHex linearly interpolates two #RRGGBB colors (t in [0,1]).
func blendHex(a, b string, t float64) string {
	ar, ag, ab := hexToRGB(a)
	br, bg, bb := hexToRGB(b)
	return fmt.Sprintf("#%02X%02X%02X", lerp(ar, br, t), lerp(ag, bg, t), lerp(ab, bb, t))
}

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
