package main

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
)

// The add-server flow: the user enters an address, a port (default 9000), and a
// friendly name. Only the name is shown in the server list afterwards, so users
// never have to think about host:port. The Cherm transport is raw TCP, so a port
// is always required at the wire level — this form keeps it out of sight with a
// sane default.

type addServerForm struct {
	address textinput.Model
	port    textinput.Model
	name    textinput.Model
	sel     int // 0 address, 1 port, 2 name
}

func newAddServerForm() addServerForm {
	mk := func(placeholder, value string, limit, width int) textinput.Model {
		in := textinput.New()
		in.Placeholder = placeholder
		in.Prompt = "> "
		in.CharLimit = limit
		in.Width = width
		if value != "" {
			in.SetValue(value)
		}
		return in
	}
	return addServerForm{
		address: mk("srv.cherm.chat", "", 128, 32),
		port:    mk("9000", "9000", 6, 10),
		name:    mk("a name for this server", "", 40, 32),
	}
}

func (f *addServerForm) inputs() []*textinput.Model {
	return []*textinput.Model{&f.address, &f.port, &f.name}
}

// focus selects field i (clamped) and blurs the rest.
func (f *addServerForm) focus(i int) {
	ins := f.inputs()
	if i < 0 {
		i = 0
	}
	if i >= len(ins) {
		i = len(ins) - 1
	}
	for j, in := range ins {
		if j == i {
			in.Focus()
		} else {
			in.Blur()
		}
	}
	f.sel = i
}

func (f *addServerForm) blurAll() {
	for _, in := range f.inputs() {
		in.Blur()
	}
}

// reset clears the form to defaults and focuses the address field.
func (f *addServerForm) reset() {
	*f = newAddServerForm()
	f.focus(0)
}

// combineHostPort builds a connectable host:port from the address + port fields.
// A scheme/path in the address is stripped; if the address already carries an
// explicit ":port" the port field is ignored.
func combineHostPort(address, port string) string {
	a := strings.TrimSpace(address)
	if i := strings.Index(a, "://"); i >= 0 {
		a = a[i+3:]
	}
	if i := strings.IndexAny(a, "/?#"); i >= 0 {
		a = a[:i]
	}
	a = strings.TrimSpace(a)
	if a == "" {
		return ""
	}
	if strings.Contains(a, ":") {
		return a
	}
	p := strings.TrimSpace(port)
	if p == "" {
		p = "9000"
	}
	return a + ":" + p
}

// addServerView renders the address / port / name form.
func (m Model) addServerView() string {
	var b strings.Builder
	b.WriteString(gradientText("✦ cherm.chat", hexMagenta, hexPink, true) + "\n\n")
	b.WriteString(menuLabel.Render("add a server"))
	b.WriteString(footerStyle.Render("  (attested before you connect)") + "\n\n")

	row := func(i int, label, hint string, in textinput.Model) {
		ls := menuKey
		if i == m.addForm.sel {
			ls = menuSel
		}
		b.WriteString(ls.Render(label))
		if hint != "" {
			b.WriteString(footerStyle.Render("  " + hint))
		}
		b.WriteString("\n" + in.View() + "\n\n")
	}
	row(0, "address", "host only, e.g. srv.cherm.chat", m.addForm.address)
	row(1, "port", "default 9000", m.addForm.port)
	row(2, "name", "shown in your server list", m.addForm.name)

	if m.checking {
		b.WriteString(statusStyle.Render("checking...") + "\n")
	} else if m.status != "" {
		// Surface check/connect errors so a failed attest is never silent.
		b.WriteString(m.statusLine() + "\n")
	}
	b.WriteString("\n" + footerStyle.Render("tab/↑↓ move · enter add & attest · esc back"))

	return m.center(panelStyle().Width(56).Render(b.String()))
}
