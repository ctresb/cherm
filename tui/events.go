package main

import "encoding/json"

// This file defines the event types that flow from the cherm-core subprocess
// (over stdout NDJSON) into the bubbletea program as tea.Msg values.
//
// The wire shapes are defined in PROTOCOL.md section 4. Each JSON line carries
// an "event" discriminator; parseEvent decodes a line into a typed tea.Msg so
// the model can switch on a concrete Go type instead of poking at maps.

// ChatInfo is one entry in the sidebar chat list (the "chats" event).
type ChatInfo struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`  // "dm" or "group"
	Title  string `json:"title"` // display label
	LastTs int64  `json:"last_ts"`
}

// Message is a single rendered message line (history + message events).
type Message struct {
	From     string `json:"from"`
	Text     string `json:"text"`
	Ts       int64  `json:"ts"` // unix millis
	Outgoing bool   `json:"outgoing"`
	Color    string `json:"color,omitempty"` // reserved for premium; "" => white
}

// --- typed tea.Msg values delivered to the model ---

type readyMsg struct {
	registered bool
	username   string
}

type statusMsg struct {
	connected  bool
	registered bool
	username   string
}

type registeredMsg struct {
	username string
	uuid     string
}

type connectedMsg struct {
	username string
	uuid     string
}

type disconnectedMsg struct {
	reason string
}

type chatsMsg struct {
	chats []ChatInfo
}

type historyMsg struct {
	chat     string
	messages []Message
}

type messageMsg struct {
	chat     string
	from     string
	text     string
	ts       int64
	outgoing bool
	color    string
}

type errorMsg struct {
	message string
	code    string
}

type infoMsg struct {
	message string
}

// pongMsg carries the measured server round-trip latency (the "pong" event).
type pongMsg struct {
	rttMs  int64
	server string
}

// coreClosedMsg is synthesized by the reader goroutine when the core's stdout
// closes (the subprocess exited). It is not part of the wire protocol.
type coreClosedMsg struct {
	err error
}

// coreEvent is the flat decode target for a single NDJSON line. Only the
// fields relevant to the line's "event" are populated.
type coreEvent struct {
	Event string `json:"event"`

	// ready / status / registered / connected
	Registered bool   `json:"registered"`
	Connected  bool   `json:"connected"`
	Username   string `json:"username"`
	UUID       string `json:"uuid"`

	// disconnected
	Reason string `json:"reason"`

	// chats
	Chats []ChatInfo `json:"chats"`

	// history
	Chat     string    `json:"chat"`
	Messages []Message `json:"messages"`

	// message
	From     string `json:"from"`
	Text     string `json:"text"`
	Ts       int64  `json:"ts"`
	Outgoing bool   `json:"outgoing"`
	Color    string `json:"color"`

	// error / info (the "message" event has no "message" JSON field, so this
	// only ever populates for error/info lines)
	Message string `json:"message"`
	Code    string `json:"code"`

	// pong
	RttMs int64 `json:"rtt_ms"`
	// (the "server" field reuses Username's sibling below; declared explicitly)
	Server string `json:"server"`
}

// parseEvent decodes one NDJSON line into a typed tea.Msg. It returns nil for
// lines it cannot understand (which the reader simply skips).
func parseEvent(line []byte) any {
	var e coreEvent
	if err := json.Unmarshal(line, &e); err != nil {
		return nil
	}
	switch e.Event {
	case "ready":
		return readyMsg{registered: e.Registered, username: e.Username}
	case "status":
		return statusMsg{connected: e.Connected, registered: e.Registered, username: e.Username}
	case "registered":
		return registeredMsg{username: e.Username, uuid: e.UUID}
	case "connected":
		return connectedMsg{username: e.Username, uuid: e.UUID}
	case "disconnected":
		return disconnectedMsg{reason: e.Reason}
	case "chats":
		return chatsMsg{chats: e.Chats}
	case "history":
		return historyMsg{chat: e.Chat, messages: e.Messages}
	case "message":
		return messageMsg{
			chat:     e.Chat,
			from:     e.From,
			text:     e.Text,
			ts:       e.Ts,
			outgoing: e.Outgoing,
			color:    e.Color,
		}
	case "error":
		return errorMsg{message: e.Message, code: e.Code}
	case "info":
		return infoMsg{message: e.Message}
	case "pong":
		return pongMsg{rttMs: e.RttMs, server: e.Server}
	default:
		return nil
	}
}
