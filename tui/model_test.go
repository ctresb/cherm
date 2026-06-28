package main

import "testing"

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
	cases := map[string]any{
		`{"event":"ready","registered":true,"username":"alice"}`:                          readyMsg{registered: true, username: "alice"},
		`{"event":"registered","username":"alice","uuid":"u1"}`:                           registeredMsg{username: "alice", uuid: "u1"},
		`{"event":"connected","username":"alice","uuid":"u1"}`:                            connectedMsg{username: "alice", uuid: "u1"},
		`{"event":"disconnected","reason":"bye"}`:                                         disconnectedMsg{reason: "bye"},
		`{"event":"message","chat":"bob","from":"bob","text":"hi","ts":123,"color":null}`: messageMsg{chat: "bob", from: "bob", text: "hi", ts: 123},
		`{"event":"error","message":"boom","code":"x"}`:                                   errorMsg{message: "boom", code: "x"},
		`{"event":"info","message":"hello"}`:                                              infoMsg{message: "hello"},
	}
	for line, want := range cases {
		got := parseEvent([]byte(line))
		if got != want {
			t.Errorf("parseEvent(%s) = %#v, want %#v", line, got, want)
		}
	}

	// chats / history carry slices, compare key bits.
	if m, ok := parseEvent([]byte(`{"event":"chats","chats":[{"id":"bob","kind":"dm","title":"bob","last_ts":9}]}`)).(chatsMsg); !ok || len(m.chats) != 1 || m.chats[0].ID != "bob" {
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
	// Unregistered -> onboarding screen.
	m := NewModel(&Core{})
	out, _ := m.Update(readyMsg{registered: false})
	mm := out.(Model)
	if mm.screen != screenOnboard {
		t.Fatalf("expected onboarding screen, got %v", mm.screen)
	}

	// Registered -> chat screen.
	m2 := NewModel(&Core{})
	out2, _ := m2.Update(readyMsg{registered: true, username: "alice"})
	mm2 := out2.(Model)
	if mm2.screen != screenChat {
		t.Fatalf("expected chat screen, got %v", mm2.screen)
	}
	if mm2.username != "alice" {
		t.Fatalf("expected username alice, got %q", mm2.username)
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
	out := renderMessage("you", 0, "hello", "")
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
