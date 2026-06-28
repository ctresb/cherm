package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// All rendering lives here. The model owns state; this file only turns that
// state into strings via lipgloss. Message bubbles stay in render.go.

// center places a panel in the middle of the window, falling back to the panel
// itself before the first WindowSizeMsg arrives.
func (m Model) center(panel string) string {
	if m.width <= 0 || m.height <= 0 {
		return panel
	}
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, panel)
}

// verdictBadge renders a tier/verdict pill: green tee, yellow software, red.
func verdictBadge(verdict, tier string) string {
	label := tier
	if label == "" {
		label = verdict
	}
	switch verdict {
	case "green":
		return badgeGreen.Render(label)
	case "yellow":
		return badgeYellow.Render(label)
	case "red":
		return badgeRed.Render(label)
	default:
		// Not attested yet — neutral, not a scary red block.
		return badgeOff.Render("unchecked")
	}
}

// ---- servers home ----

// serversView renders the list of known servers with verdict badges.
func (m Model) serversView() string {
	var b strings.Builder
	b.WriteString(gradientText("✦ cherm.chat", hexMagenta, hexPink, true))
	b.WriteString("  " + menuKey.Render("servers") + "\n\n")
	b.WriteString(menuLabel.Render("your servers"))
	b.WriteString(footerStyle.Render("  (each keeps a separate encrypted vault)") + "\n\n")

	if len(m.servers) == 0 {
		b.WriteString(footerStyle.Render("no servers yet — press ") +
			menuSel.Render("a") + footerStyle.Render(" to add one") + "\n")
	}
	for i, s := range m.servers {
		cursor := "  "
		nameStyle := menuLabel
		if i == m.serverSel {
			cursor = menuSel.Render("▸ ")
			nameStyle = menuSel
		}
		// Show the friendly name (the user never has to read host:port).
		label := s.Name
		if label == "" {
			label = s.Addr
		}
		who := s.Username
		if who == "" {
			who = "(no account)"
		}
		line := cursor + nameStyle.Render(label) + " " +
			verdictBadge(s.Verdict, s.Tier) + "  " + footerStyle.Render(who)
		if s.Active {
			line += " " + badgeOn.Render("active")
		}
		b.WriteString(line + "\n")
	}

	b.WriteString("\n" + m.statusLine())
	b.WriteString("\n" + footerStyle.Render("↑/↓ move · enter connect · a add · x remove · esc chat · q quit"))

	return m.center(panelStyle().Width(64).Render(b.String()))
}

// ---- add server (addServerView lives in addserver.go) ----

// ---- verdict ----

// verdictView renders the attestation verdict panel and the Cancel/Connect
// buttons per ATTESTATION.md.
func (m Model) verdictView() string {
	v := m.verdict
	var b strings.Builder
	b.WriteString(gradientText("✦ cherm.chat", hexMagenta, hexPink, true))
	b.WriteString("  " + menuKey.Render("server attestation") + "\n\n")

	b.WriteString(verdictBadge(v.verdict, v.tier) + "  " + menuLabel.Render(v.server) + "\n\n")

	switch v.verdict {
	case "green":
		b.WriteString(greenText.Render("safe to connect") + "\n\n")
	case "yellow":
		b.WriteString(yellowText.Render("this server has only a software signature") + "\n")
		b.WriteString(hyperlink(v.signaturesURL, linkStyle.Render("learn more ↗")) +
			footerStyle.Render("  (press o or click)") + "\n\n")
	default: // red
		b.WriteString(redText.Render("this server does not match the official ") +
			hyperlink(v.publicCodebaseURL, linkStyle.Render("public codebase")) +
			redText.Render(" — it might be dangerous") + "\n")
		b.WriteString(footerStyle.Render("press o or click to open the public codebase ↗") + "\n\n")
	}

	// Operator-supplied metadata: what codebase this server *claims* to run.
	if v.serverName != "" {
		b.WriteString(infoRow("name", truncate(v.serverName, 44)))
	}
	if v.repoURL != "" {
		b.WriteString(infoRow("claims", truncate(v.repoURL, 44)))
	}
	if v.tier != "" {
		b.WriteString(infoRow("tier", v.tier))
	}
	if v.buildHash != "" {
		b.WriteString(infoRow("build", truncate(v.buildHash, 44)))
	}
	if v.fingerprint != "" {
		b.WriteString(infoRow("fingerprint", truncate(v.fingerprint, 44)))
	}
	if v.reason != "" {
		b.WriteString(infoRow("reason", truncate(v.reason, 44)))
	}
	b.WriteString("\n")

	connectLabel := "Connect"
	connectDisabled := false
	if v.verdict == "red" {
		connectLabel = "Connect anyway"
		if m.verdictCountdown > 0 {
			connectDisabled = true
			connectLabel = fmt.Sprintf("Connect anyway (%ds)", m.verdictCountdown)
		}
	}
	b.WriteString(renderButtons(m.verdictSel, "Cancel", connectLabel, connectDisabled))
	b.WriteString("\n\n" + footerStyle.Render("←/→ or tab: move · enter: select · o: open link · esc: cancel"))

	return m.center(panelStyle().Width(66).Render(b.String()))
}

// renderButtons draws two side-by-side buttons; right may be disabled.
func renderButtons(sel int, left, right string, rightDisabled bool) string {
	render := func(label string, active, disabled bool) string {
		st := lipgloss.NewStyle().Padding(0, 2).Border(lipgloss.RoundedBorder())
		switch {
		case disabled:
			st = st.Foreground(cMuted).BorderForeground(cBorder)
		case active:
			st = st.Foreground(cDark).Background(cMagenta).BorderForeground(cMagenta).Bold(true)
		default:
			st = st.Foreground(cWhite).BorderForeground(cBorder)
		}
		return st.Render(label)
	}
	l := render(left, sel == 0, false)
	r := render(right, sel == 1, rightDisabled)
	return lipgloss.JoinHorizontal(lipgloss.Top, l, "  ", r)
}

// ---- username registration ----

// usernameView renders the centered username registration panel for a server.
func (m Model) usernameView() string {
	var b strings.Builder
	b.WriteString(gradientText("✦ cherm.chat", hexMagenta, hexPink, true))
	b.WriteString("\n\n")
	b.WriteString(menuLabel.Render("end-to-end-encrypted terminal chat") + "\n")
	b.WriteString(footerStyle.Render("server: "+m.pendingServer) + "\n\n")
	b.WriteString(menuLabel.Render("choose a username") + footerStyle.Render("  (1-16, letters & digits)") + "\n\n")
	b.WriteString(m.nameInput.View())
	b.WriteString("\n")
	if m.onboardErr != "" {
		b.WriteString("\n" + errStyle.Render(m.onboardErr))
	}
	b.WriteString("\n\n" + footerStyle.Render("enter: register   esc: back   ctrl+c: quit"))

	return m.center(panelStyle().Render(b.String()))
}

// ---- leave-chat confirmation ----

// leaveConfirmView renders the "Leave this chat?" confirmation with Leave /
// Cancel buttons (Cancel selected by default — leaving is destructive).
func (m Model) leaveConfirmView() string {
	var b strings.Builder
	b.WriteString(gradientText("✦ cherm.chat", hexMagenta, hexPink, true) + "\n\n")
	b.WriteString(menuLabel.Render("Leave this chat?") + "\n")
	b.WriteString(footerStyle.Render(m.leaveChatTitle) + "\n\n")
	b.WriteString(renderButtons(m.leaveSel, "Leave", "Cancel", false))
	b.WriteString("\n\n" + footerStyle.Render("←/→ or tab: move · enter: select · esc: cancel"))
	return m.center(panelStyle().Width(48).Render(b.String()))
}

// removeServerConfirmView renders the "Remove this server?" confirmation with
// Remove / Cancel buttons (Cancel selected by default — removal is destructive:
// it deletes the local encrypted vault for that server).
func (m Model) removeServerConfirmView() string {
	var b strings.Builder
	b.WriteString(gradientText("✦ cherm.chat", hexMagenta, hexPink, true) + "\n\n")
	b.WriteString(menuLabel.Render("Remove this server?") + "\n")
	b.WriteString(footerStyle.Render(m.removeServerAddr) + "\n")
	b.WriteString(errStyle.Render("this deletes its local vault (identity + history)") + "\n\n")
	b.WriteString(renderButtons(m.removeSel, "Remove", "Cancel", false))
	b.WriteString("\n\n" + footerStyle.Render("←/→ or tab: move · enter: select · esc: cancel"))
	return m.center(panelStyle().Width(52).Render(b.String()))
}

// ---- chat ----

// chatView renders the header + optional banners + sidebar + message pane +
// input + footer layout.
func (m Model) chatView() string {
	header := m.headerView()
	sidebar := m.sidebarView()
	mainPane := m.mainPaneView()

	body := lipgloss.JoinHorizontal(lipgloss.Top, sidebar, mainPane)

	parts := []string{header}
	// Local, never-stored banners: server maintenance countdown / waiting state,
	// then any available client update.
	if banner := m.maintenanceBanner(); banner != "" {
		parts = append(parts, banner)
	}
	if banner := m.clientUpdateBanner(); banner != "" {
		parts = append(parts, banner)
	}
	parts = append(parts, body, m.footerView())
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

// headerView is the slim top bar: gradient logo on the left, an optional safety
// number for the open DM, connection badge + user@server + a menu hint.
func (m Model) headerView() string {
	logo := gradientText("✦ cherm.chat", hexMagenta, hexPink, true)
	// Plugin-provided top-left widgets (declarative, bounded by the client).
	for _, w := range m.widgetsForSlot("top_left") {
		logo += "  " + w
	}

	badge := badgeOff.Render("offline")
	if m.connected {
		badge = badgeOn.Render("online")
	}
	who := m.username
	if who == "" {
		who = "-"
	}
	info := ""
	if fp := m.currentFingerprint(); fp != "" {
		info = lockStyle.Render("ꄗ ") + footerStyle.Render(truncate(fp, 16)+"  ")
	}
	// Plugin-provided top-right widgets (e.g. a clock).
	widget := ""
	for _, w := range m.widgetsForSlot("top_right") {
		widget += w + "  "
	}
	right := widget + info + badge + footerStyle.Render(" "+who+" @ "+m.displayServer()+"  esc: menu")

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
	// Plugin-provided status-bar widgets append to the right of the status line.
	for _, w := range m.widgetsForSlot("status") {
		line1 += footerStyle.Render("  ·  ") + w
	}

	hint := "/dm  /group  /store  /servers  /menu  /help  ·  tab focus  ·  x leave  ·  esc menu  ·  enter open/send"
	line2 := footerStyle.Render(hint)

	out := lipgloss.JoinVertical(lipgloss.Left, line1, line2)
	if m.width > 0 {
		return lipgloss.NewStyle().MaxWidth(m.width).Render(out)
	}
	return out
}

// statusLine renders the transient status as a standalone line (panel screens).
func (m Model) statusLine() string {
	if m.status == "" {
		return ""
	}
	if m.isError {
		return errStyle.Render(m.status)
	}
	return statusStyle.Render(m.status)
}

// ---- menu ----

// menuView renders the centered menu panel: server/ping/identity info, an
// actions list, and key hints.
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

	b.WriteString(infoRow("server", m.displayServer()+"  "+conn))
	b.WriteString(infoRow("ping", ping))
	b.WriteString(infoRow("user", who))
	if m.uuid != "" {
		b.WriteString(infoRow("uuid", truncate(m.uuid, 36)))
	}
	b.WriteString("\n")

	items := []string{"Change server", "Refresh ping", "Help", "Open docs ↗", "Back to chat"}
	for i, it := range items {
		if i == m.menuSel {
			b.WriteString(menuSel.Render("▸ "+it) + "\n")
		} else {
			b.WriteString("  " + menuLabel.Render(it) + "\n")
		}
	}
	b.WriteString("\n" + footerStyle.Render("↑/↓ move · enter select · r ping · esc back"))

	return m.center(panelStyle().Width(56).Render(b.String()))
}

// infoRow formats a fixed-width key + value line for the menu / verdict panels.
func infoRow(key, value string) string {
	return menuKey.Render(fmt.Sprintf("%-11s", key)) + menuLabel.Render(value) + "\n"
}

// ---- help ----

// helpView renders the centered command + key reference.
func (m Model) helpView() string {
	var b strings.Builder
	b.WriteString(gradientText("✦ cherm.chat", hexMagenta, hexPink, true))
	b.WriteString("  " + menuKey.Render("help") + "\n\n")

	b.WriteString(titleStyle.Render("commands") + "\n")
	b.WriteString(helpRow("/dm <user>", "start or open a 1:1 chat"))
	b.WriteString(helpRow("/group <name> <u...>", "create a group"))
	b.WriteString(helpRow("/servers", "switch / add a server"))
	b.WriteString(helpRow("/store", "browse & install plugins"))
	b.WriteString(helpRow("/submit", "submit a plugin to the store"))
	b.WriteString(helpRow("/update", "check for a newer client"))
	b.WriteString(helpRow("/export", "back up your account key to a file"))
	b.WriteString(helpRow("/import <file>", "restore an account key"))
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

	return m.center(panelStyle().Width(60).Render(b.String()))
}

// helpRow formats a fixed-width command/key + description line.
func helpRow(key, desc string) string {
	return menuSel.Render(fmt.Sprintf("  %-22s", key)) + footerStyle.Render(desc) + "\n"
}
