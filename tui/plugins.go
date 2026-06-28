package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Plugin store + submission UI (architecture_specification §6, §7). A theme is
// just a plugin, so this is also where the official `pastel-theme` is installed.
// Plugins are shown with their trust tier BEFORE install (§6.6), and unaudited
// community plugins are flagged use-at-your-own-risk.

// ---- category helpers ----

// categoryLabel maps a wire category to a human label.
func categoryLabel(cat string) string {
	switch cat {
	case "official":
		return "Official"
	case "community_audited":
		return "Community audited"
	case "community_unaudited":
		return "Community unaudited"
	default:
		return cat
	}
}

// categoryBadge renders a colored trust-tier pill: official=accent, audited=green,
// unaudited=red (a warning).
func categoryBadge(cat string) string {
	switch cat {
	case "official":
		return badgeOfficial.Render("Official")
	case "community_audited":
		return badgeAudited.Render("Audited")
	case "community_unaudited":
		return badgeUnaudited.Render("Unaudited")
	default:
		return badgeOff.Render(cat)
	}
}

// remainingSecs returns whole seconds left until a unix-millis deadline (>= 0).
func remainingSecs(deadlineMs int64) int {
	left := (deadlineMs - time.Now().UnixMilli()) / 1000
	if left < 0 {
		return 0
	}
	return int(left)
}

// ---- store list state helpers ----

// mergeInstalled folds the installed/active flags from an installed_plugins
// event into the store list, appending any installed plugin not in the store
// (e.g. manually installed) so it is still manageable.
func (m *Model) mergeInstalled(installed []StorePlugin) {
	byName := map[string]int{}
	for i, p := range m.storePlugins {
		byName[p.Name] = i
	}
	for _, ip := range installed {
		if i, ok := byName[ip.Name]; ok {
			m.storePlugins[i].Installed = true
			m.storePlugins[i].Active = ip.Active
			if m.storePlugins[i].Version == "" {
				m.storePlugins[i].Version = ip.Version
			}
		} else {
			ip.Installed = true
			m.storePlugins = append(m.storePlugins, ip)
		}
	}
}

// ---- store screen ----

// openStore enters the plugin store and refreshes the catalog, installed set,
// and available updates.
func (m Model) openStore() (tea.Model, tea.Cmd) {
	m.screen = screenStore
	m.input.Blur()
	m.storeChecking = true
	m.flash("loading plugin store…", false)
	return m, tea.Batch(
		m.cmdSend(map[string]any{"cmd": "list_store"}),
		m.cmdSend(map[string]any{"cmd": "list_installed"}),
		m.cmdSend(map[string]any{"cmd": "check_plugin_updates"}),
	)
}

func (m Model) updateStore(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		if m.connected {
			return m.backToChat()
		}
		m.screen = screenServers
		return m, nil
	case "up", "k":
		if m.storeSel > 0 {
			m.storeSel--
		}
		return m, nil
	case "down", "j":
		if m.storeSel < len(m.storePlugins)-1 {
			m.storeSel++
		}
		return m, nil
	case "r":
		return m.openStore()
	case "u":
		m.flash("checking for plugin updates…", false)
		return m, m.cmdSend(map[string]any{"cmd": "check_plugin_updates"})
	case "s":
		return m.openSubmit()
	case "enter", "i":
		return m.installSelectedPlugin()
	case "x":
		return m.removeSelectedPlugin()
	}
	return m, nil
}

func (m Model) selectedPlugin() *StorePlugin {
	if m.storeSel < 0 || m.storeSel >= len(m.storePlugins) {
		return nil
	}
	return &m.storePlugins[m.storeSel]
}

func (m Model) installSelectedPlugin() (tea.Model, tea.Cmd) {
	p := m.selectedPlugin()
	if p == nil {
		return m, nil
	}
	_, hasUpdate := m.pluginUpdates[p.Name]
	if p.Installed && !hasUpdate {
		m.flash(p.Name+" is already installed (press x to remove)", false)
		return m, nil
	}
	verb := "installing"
	if hasUpdate {
		verb = "updating"
	}
	m.flash(fmt.Sprintf("%s %s (%s)…", verb, p.Name, categoryLabel(p.Category)), false)
	return m, m.cmdSend(map[string]any{"cmd": "install_plugin", "name": p.Name})
}

func (m Model) removeSelectedPlugin() (tea.Model, tea.Cmd) {
	p := m.selectedPlugin()
	if p == nil || !p.Installed {
		return m, nil
	}
	m.flash("removing "+p.Name+"…", false)
	return m, m.cmdSend(map[string]any{"cmd": "remove_plugin", "name": p.Name})
}

// storeView renders the plugin store: a list with trust badges + a detail panel
// for the selection (category, description, permissions, source) shown BEFORE
// any install.
func (m Model) storeView() string {
	var b strings.Builder
	b.WriteString(gradientText("✦ cherm.chat", hexMagenta, hexPink, true))
	b.WriteString("  " + menuKey.Render("plugin store") + "\n\n")

	if len(m.storePlugins) == 0 {
		if m.storeChecking {
			b.WriteString(footerStyle.Render("loading…") + "\n")
		} else {
			b.WriteString(footerStyle.Render("no plugins found — press ") +
				menuSel.Render("r") + footerStyle.Render(" to refresh or ") +
				menuSel.Render("s") + footerStyle.Render(" to submit one") + "\n")
		}
	}

	for i, p := range m.storePlugins {
		cursor := "  "
		nameStyle := menuLabel
		if i == m.storeSel {
			cursor = menuSel.Render("▸ ")
			nameStyle = menuSel
		}
		name := p.DisplayName
		if name == "" {
			name = p.Name
		}
		line := cursor + categoryBadge(p.Category) + " " + nameStyle.Render(name) +
			footerStyle.Render(" v"+p.Version)
		if p.Installed {
			line += " " + badgeOn.Render("installed")
		}
		if _, ok := m.pluginUpdates[p.Name]; ok {
			line += " " + activityStyle.Render("update ↑")
		}
		b.WriteString(line + "\n")
	}

	// Detail panel for the current selection.
	if p := m.selectedPlugin(); p != nil {
		b.WriteString("\n" + strings.Repeat("─", 56) + "\n")
		b.WriteString(infoRow("plugin", p.DisplayName+"  v"+p.Version))
		b.WriteString(infoRow("tier", categoryLabel(p.Category)))
		if p.Category == "community_unaudited" {
			b.WriteString(redText.Render("  ! not reviewed by Cherm — install at your own risk") + "\n")
		}
		if p.Description != "" {
			b.WriteString(infoRow("about", truncate(p.Description, 44)))
		}
		if p.Author != "" {
			b.WriteString(infoRow("author", p.Author))
		}
		if p.License != "" {
			b.WriteString(infoRow("license", p.License))
		}
		if p.SourceURL != "" {
			b.WriteString(infoRow("source", truncate(p.SourceURL, 44)))
		}
		if len(p.Permissions) == 0 {
			b.WriteString(infoRow("permissions", "none"))
		} else {
			b.WriteString(menuKey.Render(fmt.Sprintf("%-11s", "permissions")) + "\n")
			for _, perm := range p.Permissions {
				b.WriteString("    " + menuLabel.Render(perm.ID) +
					footerStyle.Render(" — "+perm.Help) + "\n")
			}
		}
		if latest, ok := m.pluginUpdates[p.Name]; ok {
			b.WriteString(activityStyle.Render(fmt.Sprintf("  update available: v%s", latest)) + "\n")
		}
	}

	b.WriteString("\n" + m.statusLine())
	b.WriteString("\n" + footerStyle.Render("↑/↓ move · enter/i install · x remove · u updates · s submit · r refresh · esc back"))

	return m.center(panelStyle().Width(66).Render(b.String()))
}

// ---- submission form ----

// submitField is one editable field of the submission form.
type submitField struct {
	label string
	key   string
	input textinput.Model
}

// submitForm collects the plugin metadata required by the store.
type submitForm struct {
	fields []submitField
	sel    int
}

// newSubmitForm builds the submission form with sensible defaults.
func newSubmitForm() submitForm {
	mk := func(label, placeholder, value string) submitField {
		in := textinput.New()
		in.Placeholder = placeholder
		in.Prompt = "> "
		in.CharLimit = 256
		in.Width = 44
		if value != "" {
			in.SetValue(value)
		}
		return submitField{label: label, input: in}
	}
	f := submitForm{
		fields: []submitField{
			func() submitField { x := mk("name", "my-plugin (a-z 0-9 - _)", ""); x.key = "name"; return x }(),
			func() submitField { x := mk("version", "1.0.0", "1.0.0"); x.key = "version"; return x }(),
			func() submitField {
				x := mk("kind", "theme | widget | renderer | command", "theme")
				x.key = "kind"
				return x
			}(),
			func() submitField {
				x := mk("source_url", "https://github.com/you/plugin (public)", "")
				x.key = "source_url"
				return x
			}(),
			func() submitField { x := mk("license", "AGPL-3.0", "AGPL-3.0"); x.key = "license"; return x }(),
			func() submitField { x := mk("description", "what it does", ""); x.key = "description"; return x }(),
			func() submitField {
				x := mk("permissions", "comma list, e.g. tui.theme,tui.widget", "tui.theme")
				x.key = "permissions"
				return x
			}(),
		},
	}
	return f
}

// openSubmit enters the submission form, focusing the first field.
func (m Model) openSubmit() (tea.Model, tea.Cmd) {
	m.screen = screenSubmit
	m.input.Blur()
	m.submit = newSubmitForm()
	m.submit.sel = 0
	m.submit.fields[0].input.Focus()
	m.flash("submit a plugin — it will be listed as Community unaudited pending review", false)
	return m, textinput.Blink
}

func (m Model) updateSubmit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		return m.openStore()
	case "tab", "down":
		m.focusSubmitField(m.submit.sel + 1)
		return m, nil
	case "shift+tab", "up":
		m.focusSubmitField(m.submit.sel - 1)
		return m, nil
	case "ctrl+s":
		return m.doSubmit()
	case "enter":
		// Enter on the last field submits; otherwise advance.
		if m.submit.sel == len(m.submit.fields)-1 {
			return m.doSubmit()
		}
		m.focusSubmitField(m.submit.sel + 1)
		return m, nil
	}
	// Edit the focused field.
	var cmd tea.Cmd
	m.submit.fields[m.submit.sel].input, cmd = m.submit.fields[m.submit.sel].input.Update(msg)
	return m, cmd
}

func (m *Model) focusSubmitField(i int) {
	n := len(m.submit.fields)
	if n == 0 {
		return
	}
	if i < 0 {
		i = 0
	}
	if i >= n {
		i = n - 1
	}
	m.submit.fields[m.submit.sel].input.Blur()
	m.submit.sel = i
	m.submit.fields[i].input.Focus()
}

func (m Model) fieldValue(key string) string {
	for _, f := range m.submit.fields {
		if f.key == key {
			return strings.TrimSpace(f.input.Value())
		}
	}
	return ""
}

func (m Model) doSubmit() (tea.Model, tea.Cmd) {
	name := m.fieldValue("name")
	version := m.fieldValue("version")
	if name == "" || version == "" {
		m.flash("name and version are required", true)
		return m, nil
	}
	perms := []string{}
	for _, p := range strings.Split(m.fieldValue("permissions"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			perms = append(perms, p)
		}
	}
	manifest := map[string]any{
		"name":         name,
		"display_name": name,
		"version":      version,
		"kind":         m.fieldValue("kind"),
		"source_url":   m.fieldValue("source_url"),
		"license":      m.fieldValue("license"),
		"description":  m.fieldValue("description"),
		"permissions":  perms,
		"category":     "community_unaudited",
	}
	// Minimal declarative package; the store validates and stores it under
	// plugins.cherm.chat/{name}/…
	pkg := map[string]any{}
	m.flash("submitting "+name+"…", false)
	return m, m.cmdSend(map[string]any{"cmd": "submit_plugin", "manifest": manifest, "package": pkg})
}

func (m Model) submitView() string {
	var b strings.Builder
	b.WriteString(gradientText("✦ cherm.chat", hexMagenta, hexPink, true))
	b.WriteString("  " + menuKey.Render("submit a plugin") + "\n\n")
	b.WriteString(footerStyle.Render("all store plugins are public-source; submissions start as ") +
		badgeUnaudited.Render("Unaudited") + footerStyle.Render(" (use-at-your-own-risk) until Cherm reviews them.") + "\n\n")

	for i, f := range m.submit.fields {
		label := f.label
		ls := menuKey
		if i == m.submit.sel {
			ls = menuSel
		}
		b.WriteString(ls.Render(fmt.Sprintf("%-12s", label)) + "\n")
		b.WriteString(f.input.View() + "\n")
	}
	b.WriteString("\n" + m.statusLine())
	b.WriteString("\n" + footerStyle.Render("tab/↑↓ move · enter next · ctrl+s submit · esc back"))

	return m.center(panelStyle().Width(64).Render(b.String()))
}

// ---- widgets ----

// renderWidget renders one declarative widget to a short string, or "" if the
// client does not know how to render it (bounded by the client per §6.5).
func renderWidget(w Widget) string {
	switch w.Kind {
	case "clock":
		layout := w.Format
		if layout == "" {
			layout = "15:04:05"
		}
		return time.Now().Format(layout)
	case "text":
		return w.Value
	default:
		return ""
	}
}

// widgetsForSlot returns the rendered, styled widget strings active for a slot.
func (m Model) widgetsForSlot(slot string) []string {
	var out []string
	for _, w := range m.widgets {
		if w.Slot != slot {
			continue
		}
		if s := renderWidget(w); s != "" {
			out = append(out, badgeWidgetText.Render(s))
		}
	}
	return out
}

// ---- banners (client update / maintenance) ----

// clientUpdateBanner returns a one-line "new client available" banner, or "".
func (m Model) clientUpdateBanner() string {
	if m.clientUpdate == nil {
		return ""
	}
	msg := fmt.Sprintf(" New Cherm client available: v%s ", m.clientUpdate.latest)
	hint := footerStyle.Render("  /update-now · /update-notes · /update-ignore")
	return lipgloss.NewStyle().Foreground(cDark).Background(cMagenta).Bold(true).Render(msg) + hint
}

// maintenanceBanner returns the local maintenance countdown banner, or "".
// The countdown is computed from the deadline and rendered locally each second —
// it is never stored as chat history (install_specification §12.3).
func (m Model) maintenanceBanner() string {
	if m.waitingForServer {
		return lipgloss.NewStyle().Foreground(cDark).Background(cYellow).Bold(true).
			Render(" Server is restarting — waiting for server… reconnecting ")
	}
	if m.maintenance == nil {
		return ""
	}
	secs := remainingSecs(m.maintenance.deadlineMs)
	label := fmt.Sprintf(" ✣ System: Server will stop in %ds for update ", secs)
	return lipgloss.NewStyle().Foreground(cDark).Background(cYellow).Bold(true).Render(label)
}
