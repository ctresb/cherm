package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Message bubble rendering, kept isolated so the exact format from PROTOCOL.md
// section 6 lives in one place:
//
//	[bob][28/06/26 - 14:03:21]> hey there
//	[you][28/06/26 - 14:03:25]> hello!
//
// The "[name][DD/MM/YY - HH:MM:SS]> " prefix is bold; the body is normal
// weight. Everything renders white for now (no colors surfaced in the UI).

// timeLayout matches the protocol's DD/MM/YY - HH:MM:SS, formatted in local
// time from a unix-millis timestamp.
const timeLayout = "02/01/06 - 15:04:05"

var (
	// prefixStyle is the bold "[name][time]> " header style (palette-independent).
	prefixStyle = lipgloss.NewStyle().Bold(true)
	// bodyStyle is the normal-weight message body style.
	bodyStyle = lipgloss.NewStyle()
	// systemPrefixStyle / systemBodyStyle are palette-derived and assigned in
	// applyPalette (styles.go): accented prefix + muted italic body, so a
	// "✣ System" line is visually distinct from user chat (which stays white).
)

// renderMessage formats one message bubble.
//
// label is "you" for outgoing messages, otherwise the sender's name. The color
// argument is a per-message color hook reserved for future premium use: an
// empty string means the terminal default (white). It is never surfaced in the
// UI today, but the plumbing is kept so it can be enabled later.
//
// system marks a "✣ System" event (e.g. a "left the chat" notice): the label
// becomes "✣ System" and the prefix is accented so it reads as a system line,
// never confusable with a normal user message.
// width is the wrap width (the viewport's inner width); <=0 disables wrapping.
// outgoing marks the user's own messages, which get a subtle background band so
// they read differently from incoming ones.
func renderMessage(label string, ts int64, body, color string, system, outgoing bool, width int) string {
	if system {
		label = "✣ System"
	}
	prefix := fmt.Sprintf("[%s][%s]> ", label, time.UnixMilli(ts).Format(timeLayout))

	ps := prefixStyle
	bs := bodyStyle
	switch {
	case system:
		ps = systemPrefixStyle
		bs = systemBodyStyle
	case color != "":
		c := lipgloss.Color(color)
		ps = ps.Foreground(c)
		bs = bs.Foreground(c)
	}
	line := ps.Render(prefix) + bs.Render(body)

	// Wrap to the viewport width so long messages break onto multiple lines
	// instead of overflowing, and give outgoing messages a subtle background.
	box := lipgloss.NewStyle()
	if width > 0 {
		box = box.Width(width)
	}
	if outgoing && !system {
		box = box.Background(cOutgoingBg)
	}
	return box.Render(line)
}

// renderMessages renders an ordered slice of messages into a single string,
// wrapped to `width`, ready to drop into the viewport.
func renderMessages(msgs []Message, width int) string {
	if len(msgs) == 0 {
		return ""
	}
	lines := make([]string, 0, len(msgs))
	for _, m := range msgs {
		label := m.From
		if m.Outgoing {
			label = "you"
		}
		lines = append(lines, renderMessage(label, m.Ts, m.Text, m.Color, m.System, m.Outgoing, width))
	}
	return strings.Join(lines, "\n")
}
