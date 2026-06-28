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

// Message bubbles must stay white (premium-gated, PROTOCOL.md section 6): the
// prefix is bold but neither prefix nor body carries a foreground color.
func TestBubbleStaysWhiteAndBold(t *testing.T) {
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(termenv.ANSI)

	out := renderMessage("you", 1700000000000, "secret", "")
	if !strings.Contains(out, "\x1b[1m") {
		t.Error("bubble prefix should be bold")
	}
	if strings.Contains(out, "\x1b[38;2;") || strings.Contains(out, "\x1b[38;5;") {
		t.Error("message bubble must be white (no color) until premium is enabled")
	}
}
