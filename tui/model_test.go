package main

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestValidUsername(t *testing.T) {
	good := []string{"alice", "Bob123", "a", "0123456789abcdef"}
	bad := []string{"", "0123456789abcdefg", "has space", "dash-no", "emoji😀"}
	for _, g := range good {
		if !validUsername(g) {
			t.Errorf("expected %q to be valid", g)
		}
	}
	for _, b := range bad {
		if validUsername(b) {
			t.Errorf("expected %q to be invalid", b)
		}
	}
}

func TestParseEvent(t *testing.T) {
	// Events whose typed messages are comparable (no slices).
	cases := map[string]any{
		`{"event":"registered","server":"s:1","username":"alice","uuid":"u1"}`:                                                                  registeredMsg{server: "s:1", username: "alice", uuid: "u1"},
		`{"event":"connected","server":"s:1","username":"alice","active":true}`:                                                                 connectedMsg{server: "s:1", username: "alice", active: true},
		`{"event":"disconnected","server":"s:1","reason":"bye"}`:                                                                                disconnectedMsg{server: "s:1", reason: "bye"},
		`{"event":"need_username","server":"s:1"}`:                                                                                              needUsernameMsg{server: "s:1"},
		`{"event":"message","chat":"bob","from":"bob","text":"hi","ts":123,"color":null}`:                                                       messageMsg{chat: "bob", from: "bob", text: "hi", ts: 123},
		`{"event":"fingerprint","username":"bob","fingerprint":"AB CD EF"}`:                                                                     fingerprintMsg{username: "bob", fingerprint: "AB CD EF"},
		`{"event":"error","message":"boom","code":"x"}`:                                                                                         errorMsg{message: "boom", code: "x"},
		`{"event":"info","message":"hello"}`:                                                                                                    infoMsg{message: "hello"},
		`{"event":"pong","rtt_ms":12,"server":"s:1"}`:                                                                                           pongMsg{rttMs: 12, server: "s:1"},
		`{"event":"attest","server":"s:1","verdict":"red","tier":"unsigned","public_codebase_url":"https://gh","signatures_url":"https://sig"}`: attestMsg{server: "s:1", verdict: "red", tier: "unsigned", publicCodebaseURL: "https://gh", signaturesURL: "https://sig"},
	}
	for line, want := range cases {
		got := parseEvent([]byte(line))
		if got != want {
			t.Errorf("parseEvent(%s) = %#v, want %#v", line, got, want)
		}
	}

	// ready / servers / chats / history carry slices: compare key bits.
	if m, ok := parseEvent([]byte(`{"event":"ready","has_master":true,"servers":[{"id":"i","addr":"s:1","tier":"tee","verdict":"green","active":true}]}`)).(readyMsg); !ok || !m.hasMaster || len(m.servers) != 1 || m.servers[0].Addr != "s:1" || m.servers[0].Verdict != "green" {
		t.Errorf("ready parse failed: %#v", m)
	}
	if m, ok := parseEvent([]byte(`{"event":"servers","servers":[{"addr":"s:1","tier":"software","verdict":"yellow","username":"alice"}]}`)).(serversMsg); !ok || len(m.servers) != 1 || m.servers[0].Username != "alice" {
		t.Errorf("servers parse failed: %#v", m)
	}
	if m, ok := parseEvent([]byte(`{"event":"chats","server":"s:1","chats":[{"id":"bob","kind":"dm","title":"bob","last_ts":9}]}`)).(chatsMsg); !ok || m.server != "s:1" || len(m.chats) != 1 || m.chats[0].ID != "bob" {
		t.Errorf("chats parse failed: %#v", m)
	}
	if m, ok := parseEvent([]byte(`{"event":"history","chat":"bob","messages":[{"from":"bob","text":"hi","ts":1,"outgoing":false}]}`)).(historyMsg); !ok || m.chat != "bob" || len(m.messages) != 1 {
		t.Errorf("history parse failed: %#v", m)
	}

	if parseEvent([]byte(`not json`)) != nil {
		t.Error("expected nil for invalid json")
	}
}

func TestReadyFlow(t *testing.T) {
	// No known servers -> add-server screen.
	m := NewModel(&Core{})
	out, _ := m.Update(readyMsg{servers: nil, hasMaster: false})
	mm := out.(Model)
	if mm.screen != screenAddServer {
		t.Fatalf("expected add-server screen, got %v", mm.screen)
	}

	// Known servers -> servers home screen.
	m2 := NewModel(&Core{})
	out2, _ := m2.Update(readyMsg{
		servers:   []ServerInfo{{Addr: "chat:9000", Tier: "tee", Verdict: "green", Username: "alice", Active: true}},
		hasMaster: true,
	})
	mm2 := out2.(Model)
	if mm2.screen != screenServers {
		t.Fatalf("expected servers screen, got %v", mm2.screen)
	}
	if len(mm2.servers) != 1 || mm2.servers[0].Addr != "chat:9000" {
		t.Fatalf("expected one known server, got %#v", mm2.servers)
	}
}

func TestAttestVerdictFlow(t *testing.T) {
	// A green verdict goes to the verdict screen with Connect focused and no
	// countdown.
	m := NewModel(&Core{})
	out, _ := m.Update(attestMsg{server: "s:1", verdict: "green", tier: "tee", buildHash: "abc"})
	mm := out.(Model)
	if mm.screen != screenVerdict {
		t.Fatalf("expected verdict screen, got %v", mm.screen)
	}
	if mm.verdictSel != 1 {
		t.Fatalf("green verdict should default to Connect, got sel=%d", mm.verdictSel)
	}
	if mm.verdictCountdown != 0 {
		t.Fatalf("green verdict should have no countdown, got %d", mm.verdictCountdown)
	}

	// A red verdict starts a 10s countdown defaulting to Cancel; Connect anyway
	// must be blocked until it elapses.
	mr := NewModel(&Core{})
	outr, cmd := mr.Update(attestMsg{server: "evil:9000", verdict: "red", tier: "unsigned", publicCodebaseURL: "https://gh"})
	mmr := outr.(Model)
	if mmr.verdictCountdown != redCountdownSecs {
		t.Fatalf("red verdict should start a %ds countdown, got %d", redCountdownSecs, mmr.verdictCountdown)
	}
	if mmr.verdictSel != 0 {
		t.Fatalf("red verdict should default to Cancel, got sel=%d", mmr.verdictSel)
	}
	if cmd == nil {
		t.Fatalf("red verdict should schedule a countdown tick")
	}

	// Selecting Connect anyway while counting down does not connect.
	mmr.verdictSel = 1
	out2, cmd2 := mmr.Update(tea.KeyMsg{Type: tea.KeyEnter})
	mmr = out2.(Model)
	if mmr.screen != screenVerdict {
		t.Fatalf("Connect anyway during countdown should stay on verdict screen")
	}
	_ = cmd2

	// Ticks decrement the countdown; once it hits zero Connect anyway works.
	for mmr.verdictCountdown > 0 {
		o, _ := mmr.Update(verdictTickMsg{})
		mmr = o.(Model)
	}
	out3, cmd3 := mmr.Update(tea.KeyMsg{Type: tea.KeyEnter})
	mmr = out3.(Model)
	if cmd3 == nil {
		t.Fatalf("Connect anyway after countdown should issue a connect command")
	}
}

func TestNeedUsernameFlow(t *testing.T) {
	m := NewModel(&Core{})
	out, _ := m.Update(needUsernameMsg{server: "chat:9000"})
	mm := out.(Model)
	if mm.screen != screenUsername {
		t.Fatalf("expected username screen, got %v", mm.screen)
	}
	if mm.pendingServer != "chat:9000" {
		t.Fatalf("expected pendingServer chat:9000, got %q", mm.pendingServer)
	}
}

func TestConnectedEntersChat(t *testing.T) {
	m := NewModel(&Core{})
	out, _ := m.Update(connectedMsg{server: "chat:9000", username: "alice", active: true})
	mm := out.(Model)
	if mm.screen != screenChat {
		t.Fatalf("expected chat screen after connected, got %v", mm.screen)
	}
	if mm.serverAddr != "chat:9000" || mm.username != "alice" || !mm.connected {
		t.Fatalf("connected state not applied: %+v", mm)
	}
}

func TestFingerprintStored(t *testing.T) {
	m := NewModel(&Core{})
	out, _ := m.Update(fingerprintMsg{username: "bob", fingerprint: "AB CD EF"})
	mm := out.(Model)
	if mm.fingerprints["bob"] != "AB CD EF" {
		t.Fatalf("expected fingerprint stored for bob, got %q", mm.fingerprints["bob"])
	}
}

func TestMessageRoutingActivity(t *testing.T) {
	m := NewModel(&Core{})
	m.screen = screenChat
	m.current = "bob"
	m.chatByID["bob"] = &chatState{info: ChatInfo{ID: "bob", Kind: "dm", Title: "bob"}}
	m.chats = []*chatState{m.chatByID["bob"]}

	// Message to the open chat: appended, no activity flag.
	out, _ := m.Update(messageMsg{chat: "bob", from: "bob", text: "hey", ts: 1})
	m = out.(Model)
	if len(m.chatByID["bob"].messages) != 1 {
		t.Fatalf("expected 1 message in open chat")
	}
	if m.chatByID["bob"].activity {
		t.Fatalf("open chat should not be marked as activity")
	}

	// Message to a different chat: creates it and marks activity.
	out2, _ := m.Update(messageMsg{chat: "carol", from: "carol", text: "yo", ts: 2})
	m = out2.(Model)
	cs := m.chatByID["carol"]
	if cs == nil || !cs.activity {
		t.Fatalf("expected new chat carol with activity flag")
	}
}

func TestMessageAutoScrollStickiness(t *testing.T) {
	m := NewModel(&Core{})
	m.screen = screenChat
	m.current = "bob"
	cs := &chatState{info: ChatInfo{ID: "bob", Kind: "dm", Title: "bob"}}
	// Backlog larger than the viewport height so AtBottom is meaningful.
	for i := 0; i < 10; i++ {
		cs.messages = append(cs.messages, Message{From: "bob", Text: "line", Ts: int64(i + 1)})
	}
	m.chatByID["bob"] = cs
	m.chats = []*chatState{cs}

	m.viewport.Width = 40
	m.viewport.Height = 3
	m.refreshViewport()
	if !m.viewport.AtBottom() {
		t.Fatalf("expected viewport pinned to bottom after refresh")
	}

	// Reader scrolled up: an incoming message must NOT yank them to the bottom.
	m.viewport.GotoTop()
	off := m.viewport.YOffset
	out, _ := m.Update(messageMsg{chat: "bob", from: "bob", text: "new", ts: 100})
	m = out.(Model)
	if m.viewport.YOffset != off {
		t.Fatalf("scrolled-up viewport moved on incoming message: YOffset=%d want %d", m.viewport.YOffset, off)
	}
	if m.viewport.AtBottom() {
		t.Fatalf("scrolled-up viewport should not jump to bottom on incoming message")
	}

	// Reader at the bottom: an incoming message should follow the tail.
	m.viewport.GotoBottom()
	out2, _ := m.Update(messageMsg{chat: "bob", from: "bob", text: "newer", ts: 101})
	m = out2.(Model)
	if !m.viewport.AtBottom() {
		t.Fatalf("at-bottom viewport should follow the newest message")
	}
}

func TestRenderMessage(t *testing.T) {
	// ts 0 -> epoch; just assert the structural prefix and body are present.
	out := renderMessage("you", 0, "hello", "", false)
	if !contains(out, "[you][") || !contains(out, "]> ") || !contains(out, "hello") {
		t.Fatalf("unexpected render: %q", out)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
