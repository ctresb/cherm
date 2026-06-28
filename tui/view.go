package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// All rendering for the two screens lives here. The model owns state; this file
// only turns that state into strings via lipgloss.

// onboardView renders the centered username registration panel.
func (m Model) onboardView() string {
	var b strings.Builder
	b.WriteString(gradientText("✦ cherm.chat", hexMagenta, hexPink, true))
	b.WriteString("\n\n")
	b.WriteString(menuLabel.Render("end-to-end-encrypted terminal chat") + "\n")
	b.WriteString(footerStyle.Render("server: "+m.serverAddr) + "\n\n")
	b.WriteString(menuLabel.Render("choose a username") + footerStyle.Render("  (1-16, letters & digits)") + "\n\n")
	b.WriteString(m.nameInput.View())
	b.WriteString("\n")
	if m.onboardErr != "" {
		b.WriteString("\n" + errStyle.Render(m.onboardErr))
	}
	b.WriteString("\n\n" + footerStyle.Render("enter: register   ctrl+c: quit"))

	panel := panelStyle().Render(b.String())
	if m.width <= 0 || m.height <= 0 {
		return panel
	}
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, panel)
}

// chatView renders the header + sidebar + message pane + input + footer layout.
func (m Model) chatView() string {
	header := m.headerView()
	sidebar := m.sidebarView()
	mainPane := m.mainPaneView()

	body := lipgloss.JoinHorizontal(lipgloss.Top, sidebar, mainPane)
	return lipgloss.JoinVertical(lipgloss.Left, header, body, m.footerView())
}

// headerView is the slim top bar: gradient logo on the left, connection badge +
// server + a menu hint on the right.
func (m Model) headerView() string {
	logo := gradientText("✦ cherm.chat", hexMagenta, hexPink, true)

	badge := badgeOff.Render("offline")
	if m.connected {
		badge = badgeOn.Render("online")
	}
	right := badge + footerStyle.Render(" "+m.serverAddr+"  esc: menu")

	if m.width <= 0 {
		return logo + "   " + right
	}
	gap := m.width - lipgloss.Width(logo) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	line := logo + strings.Repeat(" ", gap) + right
	return lipgloss.NewStyle().MaxWidth(m.width).Render(line)
}

// sidebarView renders the bordered chat list.
func (m Model) sidebarView() string {
	innerW := clampMin(m.sidebarW-2, 1)

	var b strings.Builder
	b.WriteString(titleStyle.Render("chats"))
	b.WriteString("\n\n")

	if len(m.chats) == 0 {
		b.WriteString(footerStyle.Render("no chats yet\n\nuse /dm <user>"))
	}
	for i, cs := range m.chats {
		name := cs.info.Title
		if name == "" {
			name = cs.info.ID
		}
		if cs.info.Kind == "group" {
			name = "#" + name
		}

		label := truncate(name, innerW-2)
		if i == m.sidebarSel {
			// Selected row: a full-width magenta pill.
			b.WriteString(selectedStyle.Width(innerW).Render(" "+label) + "\n")
			continue
		}
		dot := "  "
		if cs.activity {
			dot = activityStyle.Render("• ")
		}
		b.WriteString(dot + itemStyle.Render(label) + "\n")
	}

	return boxStyle(m.focus == focusSidebar).
		Width(innerW).
		Height(clampMin(m.contentH-2, 1)).
		Render(b.String())
}

// mainPaneView stacks the message viewport on top of the input box.
func (m Model) mainPaneView() string {
	vp := boxStyle(false).
		Width(m.viewport.Width).
		Height(m.viewport.Height).
		Render(m.viewport.View())

	in := boxStyle(m.focus == focusInput).
		Width(m.viewport.Width).
		Render(m.input.View())

	return lipgloss.JoinVertical(lipgloss.Left, vp, in)
}

// footerView shows the transient status line and a short command hint.
func (m Model) footerView() string {
	conn := "offline"
	if m.connected {
		conn = "online"
	}
	who := m.username
	if who == "" {
		who = "-"
	}
	open := m.current
	if open == "" {
		open = "(none)"
	}

	status := m.status
	style := statusStyle
	if m.isError {
		style = errStyle
	}

	left := fmt.Sprintf("%s @ %s | chat: %s", who, conn, open)
	line1 := footerStyle.Render(left)
	if status != "" {
		line1 = footerStyle.Render(left+"  |  ") + style.Render(status)
	}

	hint := "/dm  /group  /menu  /help  /quit  ·  tab: focus  ·  esc: menu  ·  enter: open/send"
	line2 := footerStyle.Render(hint)

	out := lipgloss.JoinVertical(lipgloss.Left, line1, line2)
	if m.width > 0 {
		return lipgloss.NewStyle().MaxWidth(m.width).Render(out)
	}
	return out
}

// menuView renders the centered menu panel: server/ping/identity info, an
// actions list (or the server-address editor), and key hints.
func (m Model) menuView() string {
	var b strings.Builder
	b.WriteString(gradientText("✦ cherm.chat", hexMagenta, hexPink, true))
	b.WriteString("  " + menuKey.Render("menu") + "\n\n")

	conn := badgeOff.Render("offline")
	if m.connected {
		conn = badgeOn.Render("online")
	}
	ping := "—"
	if m.pingMs >= 0 {
		ping = fmt.Sprintf("%d ms", m.pingMs)
	}
	who := m.username
	if who == "" {
		who = "-"
	}

	b.WriteString(infoRow("server", m.serverAddr+"  "+conn))
	b.WriteString(infoRow("ping", ping))
	b.WriteString(infoRow("user", who))
	if m.uuid != "" {
		b.WriteString(infoRow("uuid", truncate(m.uuid, 36)))
	}
	b.WriteString("\n")

	if m.menuEditing {
		b.WriteString(menuLabel.Render("new server address:") + "\n\n")
		b.WriteString(m.serverInput.View() + "\n\n")
		b.WriteString(footerStyle.Render("enter: connect   ·   esc: cancel"))
	} else {
		items := []string{"Change server", "Refresh ping", "Help", "Open docs ↗", "Back to chat"}
		for i, it := range items {
			if i == m.menuSel {
				b.WriteString(menuSel.Render("▸ "+it) + "\n")
			} else {
				b.WriteString("  " + menuLabel.Render(it) + "\n")
			}
		}
		b.WriteString("\n" + footerStyle.Render("↑/↓ move · enter select · r ping · esc back"))
	}

	panel := panelStyle().Width(56).Render(b.String())
	if m.width <= 0 || m.height <= 0 {
		return panel
	}
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, panel)
}

// infoRow formats a fixed-width key + value line for the menu.
func infoRow(key, value string) string {
	return menuKey.Render(fmt.Sprintf("%-9s", key)) + menuLabel.Render(value) + "\n"
}

// helpView renders the centered command + key reference.
func (m Model) helpView() string {
	var b strings.Builder
	b.WriteString(gradientText("✦ cherm.chat", hexMagenta, hexPink, true))
	b.WriteString("  " + menuKey.Render("help") + "\n\n")

	b.WriteString(titleStyle.Render("commands") + "\n")
	b.WriteString(helpRow("/dm <user>", "start or open a 1:1 chat"))
	b.WriteString(helpRow("/group <name> <u...>", "create a group"))
	b.WriteString(helpRow("/menu", "server, ping, docs"))
	b.WriteString(helpRow("/help", "show this help"))
	b.WriteString(helpRow("/quit", "exit"))
	b.WriteString("\n")

	b.WriteString(titleStyle.Render("keys") + "\n")
	b.WriteString(helpRow("tab", "switch chat list / input"))
	b.WriteString(helpRow("↑/↓", "move selection / scroll"))
	b.WriteString(helpRow("enter", "open chat / send message"))
	b.WriteString(helpRow("esc", "open menu / go back"))
	b.WriteString(helpRow("pgup/pgdn", "scroll messages"))
	b.WriteString(helpRow("ctrl+c", "quit"))
	b.WriteString("\n" + footerStyle.Render("press esc or enter to go back"))

	panel := panelStyle().Width(60).Render(b.String())
	if m.width <= 0 || m.height <= 0 {
		return panel
	}
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, panel)
}

// helpRow formats a fixed-width command/key + description line.
func helpRow(key, desc string) string {
	return menuSel.Render(fmt.Sprintf("  %-22s", key)) + footerStyle.Render(desc) + "\n"
}
