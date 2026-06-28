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
	// prefixStyle is the bold "[name][time]> " header style.
	prefixStyle = lipgloss.NewStyle().Bold(true)
	// bodyStyle is the normal-weight message body style.
	bodyStyle = lipgloss.NewStyle()
)

// renderMessage formats one message bubble.
//
// label is "you" for outgoing messages, otherwise the sender's name. The color
// argument is a per-message color hook reserved for future premium use: an
// empty string means the terminal default (white). It is never surfaced in the
// UI today, but the plumbing is kept so it can be enabled later.
func renderMessage(label string, ts int64, body, color string) string {
	prefix := fmt.Sprintf("[%s][%s]> ", label, time.UnixMilli(ts).Format(timeLayout))

	ps := prefixStyle
	bs := bodyStyle
	if color != "" {
		c := lipgloss.Color(color)
		ps = ps.Foreground(c)
		bs = bs.Foreground(c)
	}
	return ps.Render(prefix) + bs.Render(body)
}

// renderMessages renders an ordered slice of messages into a single string,
// one bubble per line, ready to drop into the viewport.
func renderMessages(msgs []Message) string {
	if len(msgs) == 0 {
		return ""
	}
	lines := make([]string, 0, len(msgs))
	for _, m := range msgs {
		label := m.From
		if m.Outgoing {
			label = "you"
		}
		lines = append(lines, renderMessage(label, m.Ts, m.Text, m.Color))
	}
	return strings.Join(lines, "\n")
}
