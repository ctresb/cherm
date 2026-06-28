package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// TestSnapshot writes colored ANSI frames of each screen to $CHERM_SNAPSHOT_DIR
// when set, so the rendered UI can be eyeballed. It is a no-op otherwise.
func TestSnapshot(t *testing.T) {
	dir := os.Getenv("CHERM_SNAPSHOT_DIR")
	if dir == "" {
		t.Skip("set CHERM_SNAPSHOT_DIR to dump frames")
	}
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(termenv.ANSI)
	for name, s := range map[string]screen{"chat": screenChat, "menu": screenMenu, "help": screenHelp} {
		_ = os.WriteFile(dir+"/"+name+".ansi", []byte(renderModel(s).View()), 0o644)
	}
	// servers home
	sv := renderModel(screenServers)
	sv.servers = []ServerInfo{
		{Addr: "chat.cherm.example:9000", Tier: "tee", Verdict: "green", Username: "alice", Active: true},
		{Addr: "relay.example:9000", Tier: "software", Verdict: "yellow", Username: ""},
		{Addr: "sketchy.example:9000", Tier: "unsigned", Verdict: "red", Username: ""},
	}
	_ = os.WriteFile(dir+"/servers.ansi", []byte(sv.View()), 0o644)
	// the three verdict screens
	verdicts := map[string]attestMsg{
		"verdict_green":  {server: "chat.cherm.example:9000", verdict: "green", tier: "tee", buildHash: "abc123def456", fingerprint: "AA BB CC DD"},
		"verdict_yellow": {server: "relay.example:9000", verdict: "yellow", tier: "software", buildHash: "abc123def456", signaturesURL: "https://cherm.chat/signatures"},
		"verdict_red":    {server: "sketchy.example:9000", verdict: "red", tier: "unsigned", reason: "server provided no signature", publicCodebaseURL: "https://github.com/cherm-chat/cherm"},
	}
	for name, v := range verdicts {
		vm := renderModel(screenVerdict)
		vm.verdict = v
		if v.verdict == "red" {
			vm.verdictCountdown = 7
		}
		_ = os.WriteFile(dir+"/"+name+".ansi", []byte(vm.View()), 0o644)
	}
}

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;?]*[a-zA-Z]")

// strip removes ANSI escapes so text assertions are not defeated by the
// per-rune color codes the gradient inserts between characters.
func strip(s string) string { return ansiRE.ReplaceAllString(s, "") }

// renderModel builds a fully-populated model parked on the given screen so the
// View() output can be asserted deterministically (no PTY, no timing).
func renderModel(s screen) Model {
	m := NewModel(NewCore())
	m.ready = true
	m.width, m.height = 120, 32
	m.connected = true
	m.username = "alice"
	m.uuid = "1f2e3d4c-aaaa-bbbb-cccc-dddddddddddd"
	m.serverAddr = "chat.cherm.example:9000"
	m.pingMs = 12

	cs := &chatState{
		info: ChatInfo{ID: "bob", Kind: "dm", Title: "bob"},
		messages: []Message{
			{From: "bob", Text: "hey there", Ts: 1700000000000, Outgoing: false},
			{From: "alice", Text: "hello!", Ts: 1700000005000, Outgoing: true},
		},
	}
	m.chats = []*chatState{cs}
	m.chatByID = map[string]*chatState{"bob": cs}
	m.current = "bob"
	m.screen = s
	m.layout()
	return m
}

// EE00FF = (238, 0, 255): the exact magenta truecolor SGR proves the palette
// (and the gradient, which starts at this color) is actually applied.
const magentaSGR = "\x1b[38;2;238;0;255m"

func TestRenderScreensAndPalette(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(termenv.ANSI)
	// Pin the default palette so the assertion is deterministic regardless of any
	// theme plugin active in the developer's ~/.cherm (init() loads it from disk).
	applyPalette(defaultPalette())
	defer applyPalette(loadPaletteFromDisk())

	chatRaw := renderModel(screenChat).View()
	chat := strip(chatRaw)
	for _, want := range []string{"cherm.chat", "online", "chat.cherm.example:9000", "[bob][", "]> ", "hello!"} {
		if !strings.Contains(chat, want) {
			t.Errorf("chat view missing %q", want)
		}
	}
	if !strings.Contains(chatRaw, magentaSGR) {
		t.Error("chat view did not emit the EE00FF magenta (palette/gradient inactive)")
	}

	menu := strip(renderModel(screenMenu).View())
	for _, want := range []string{"menu", "Change server", "Refresh ping", "Open docs", "12 ms", "chat.cherm.example:9000"} {
		if !strings.Contains(menu, want) {
			t.Errorf("menu view missing %q", want)
		}
	}

	help := strip(renderModel(screenHelp).View())
	for _, want := range []string{"/dm", "/group", "/menu", "ctrl+c", "switch chat list"} {
		if !strings.Contains(help, want) {
			t.Errorf("help view missing %q", want)
		}
	}
}

// TestRenderServerScreens exercises the v2 multi-server + attestation screens.
func TestRenderServerScreens(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(termenv.ANSI)

	// servers home: addr + verdict badge + active marker.
	m := renderModel(screenServers)
	m.servers = []ServerInfo{
		{Addr: "chat.cherm.example:9000", Tier: "tee", Verdict: "green", Username: "alice", Active: true},
		{Addr: "relay.example:9000", Tier: "software", Verdict: "yellow", Username: ""},
	}
	servers := strip(m.View())
	for _, want := range []string{"servers", "chat.cherm.example:9000", "tee", "relay.example:9000", "software", "(no account)", "active", "remove"} {
		if !strings.Contains(servers, want) {
			t.Errorf("servers view missing %q", want)
		}
	}

	// add-server: prompt + checking indicator.
	a := renderModel(screenAddServer)
	a.checking = true
	add := strip(a.View())
	for _, want := range []string{"add a server", "address", "port", "name", "checking..."} {
		if !strings.Contains(add, want) {
			t.Errorf("add-server view missing %q", want)
		}
	}

	// red verdict: dangerous wording, "public codebase" highlight, disabled
	// "Connect anyway" with a live countdown.
	r := renderModel(screenVerdict)
	r.verdict = attestMsg{server: "evil:9000", verdict: "red", tier: "unsigned", buildHash: "deadbeef", publicCodebaseURL: "https://github.com/cherm-chat/cherm"}
	r.verdictCountdown = 7
	r.verdictSel = 0
	red := strip(r.View())
	for _, want := range []string{"does not match", "public codebase", "Cancel", "Connect anyway", "7s"} {
		if !strings.Contains(red, want) {
			t.Errorf("red verdict view missing %q", want)
		}
	}

	// yellow verdict: software-signature wording + learn more.
	y := renderModel(screenVerdict)
	y.verdict = attestMsg{server: "relay:9000", verdict: "yellow", tier: "software", signaturesURL: "https://cherm.chat/signatures"}
	y.verdictCountdown = 0
	y.verdictSel = 1
	yellow := strip(y.View())
	for _, want := range []string{"software signature", "learn more", "Connect"} {
		if !strings.Contains(yellow, want) {
			t.Errorf("yellow verdict view missing %q", want)
		}
	}

	// green verdict: safe-to-connect + details.
	g := renderModel(screenVerdict)
	g.verdict = attestMsg{server: "chat:9000", verdict: "green", tier: "tee", buildHash: "abc123", fingerprint: "AA BB CC"}
	green := strip(g.View())
	for _, want := range []string{"safe to connect", "tee", "Connect", "Cancel"} {
		if !strings.Contains(green, want) {
			t.Errorf("green verdict view missing %q", want)
		}
	}

	// username screen.
	u := renderModel(screenUsername)
	u.pendingServer = "chat:9000"
	user := strip(u.View())
	for _, want := range []string{"choose a username", "chat:9000"} {
		if !strings.Contains(user, want) {
			t.Errorf("username view missing %q", want)
		}
	}
}

func TestReservedUsernames(t *testing.T) {
	for _, n := range []string{"System", "system", "Server", "server", "SeRvEr"} {
		if !isReservedUsername(n) {
			t.Errorf("%q must be reserved", n)
		}
	}
	if isReservedUsername("alice") {
		t.Error("alice must not be reserved")
	}
	if !validUsername("system") || isReservedUsername("alice") {
		t.Error("sanity: 'system' is valid charset but reserved")
	}
}

func TestLeaveConfirmView(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(termenv.ANSI)
	m := renderModel(screenLeaveConfirm)
	m.leaveChatID = "bob"
	m.leaveChatTitle = "bob"
	m.leaveSel = 1
	out := strip(m.View())
	for _, want := range []string{"Leave this chat?", "Leave", "Cancel", "bob"} {
		if !strings.Contains(out, want) {
			t.Errorf("leave-confirm view missing %q", want)
		}
	}
}

// Message bubbles must stay white (premium-gated, PROTOCOL.md section 6): the
// prefix is bold but neither prefix nor body carries a foreground color.
func TestBubbleStaysWhiteAndBold(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(termenv.ANSI)

	// A system "left the chat" line renders as "✣ System", never as a user.
	sys := renderMessage("alice", 1700000000000, "alice left the chat.", "", true, false, 0)
	if !strings.Contains(strip(sys), "✣ System") {
		t.Error("system message must render as ✣ System")
	}
	if !strings.Contains(strip(sys), "left the chat.") {
		t.Error("system message must carry the notice text")
	}

	out := renderMessage("you", 1700000000000, "secret", "", false, true, 0)
	// Prefix is bold. The outgoing background band merges the bold attribute with
	// the bg (e.g. "\x1b[1;48;2;...m"), so accept either standalone or combined.
	if !strings.Contains(out, "\x1b[1m") && !strings.Contains(out, "\x1b[1;") {
		t.Error("bubble prefix should be bold")
	}
	// No FOREGROUND color until premium (a background tint band is allowed).
	if strings.Contains(out, "\x1b[38;2;") || strings.Contains(out, "\x1b[38;5;") {
		t.Error("message bubble must be white (no foreground color) until premium is enabled")
	}
}
