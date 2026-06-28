package main

import "encoding/json"

// This file defines the event types that flow from the cherm-core subprocess
// (over stdout NDJSON) into the bubbletea program as tea.Msg values.
//
// The wire shapes are defined in PROTOCOL.md section 4. Each JSON line carries
// an "event" discriminator; parseEvent decodes a line into a typed tea.Msg so
// the model can switch on a concrete Go type instead of poking at maps.

// ServerInfo is one entry in the known-servers list ("ready" / "servers"
// events). Username is the empty string when no account exists on that server.
type ServerInfo struct {
	ID       string `json:"id"`
	Addr     string `json:"addr"`
	Tier     string `json:"tier"`    // "unsigned" | "software" | "tee"
	Verdict  string `json:"verdict"` // "green" | "yellow" | "red"
	Username string `json:"username"`
	Active   bool   `json:"active"`
}

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
	System   bool   `json:"system,omitempty"` // a "✣ System" event (e.g. a leave notice)
}

// --- typed tea.Msg values delivered to the model ---

type readyMsg struct {
	servers   []ServerInfo
	hasMaster bool
}

type serversMsg struct {
	servers []ServerInfo
}

// attestMsg carries an attestation verdict for a server (the "attest" event).
type attestMsg struct {
	server            string
	verdict           string // "green" | "yellow" | "red"
	tier              string // "unsigned" | "software" | "tee"
	reason            string
	buildHash         string
	fingerprint       string
	publicCodebaseURL string
	signaturesURL     string
	// operator-supplied public metadata (what codebase the server claims to run)
	serverName  string
	repoURL     string
	description string
}

type needUsernameMsg struct {
	server string
}

type registeredMsg struct {
	server   string
	username string
	uuid     string
}

type connectedMsg struct {
	server   string
	username string
	active   bool
}

type disconnectedMsg struct {
	server string
	reason string
}

type chatsMsg struct {
	server string
	chats  []ChatInfo
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
	system   bool
}

// fingerprintMsg carries a peer's safety number (the "fingerprint" event).
type fingerprintMsg struct {
	username    string
	fingerprint string
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

	// ready / servers
	Servers   []ServerInfo `json:"servers"`
	HasMaster bool         `json:"has_master"`

	// identity / connection state
	Username string `json:"username"`
	UUID     string `json:"uuid"`
	Active   bool   `json:"active"`

	// server-scoped events (attest / need_username / connected / chats / pong …)
	Server string `json:"server"`

	// attest
	Verdict           string `json:"verdict"`
	Tier              string `json:"tier"`
	Reason            string `json:"reason"` // also reused by "disconnected"
	BuildHash         string `json:"build_hash"`
	Fingerprint       string `json:"fingerprint"` // also reused by "fingerprint"
	PublicCodebaseURL string `json:"public_codebase_url"`
	SignaturesURL     string `json:"signatures_url"`
	ServerName        string `json:"server_name"`
	RepoURL           string `json:"repo_url"`
	Description       string `json:"description"`

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
	System   bool   `json:"system"`

	// error / info (the "message" event has no "message" JSON field, so this
	// only ever populates for error/info lines)
	Message string `json:"message"`
	Code    string `json:"code"`

	// pong
	RttMs int64 `json:"rtt_ms"`
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
		return readyMsg{servers: e.Servers, hasMaster: e.HasMaster}
	case "servers":
		return serversMsg{servers: e.Servers}
	case "attest":
		return attestMsg{
			server:            e.Server,
			verdict:           e.Verdict,
			tier:              e.Tier,
			reason:            e.Reason,
			buildHash:         e.BuildHash,
			fingerprint:       e.Fingerprint,
			publicCodebaseURL: e.PublicCodebaseURL,
			signaturesURL:     e.SignaturesURL,
			serverName:        e.ServerName,
			repoURL:           e.RepoURL,
			description:       e.Description,
		}
	case "need_username":
		return needUsernameMsg{server: e.Server}
	case "registered":
		return registeredMsg{server: e.Server, username: e.Username, uuid: e.UUID}
	case "connected":
		return connectedMsg{server: e.Server, username: e.Username, active: e.Active}
	case "disconnected":
		return disconnectedMsg{server: e.Server, reason: e.Reason}
	case "chats":
		return chatsMsg{server: e.Server, chats: e.Chats}
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
			system:   e.System,
		}
	case "fingerprint":
		return fingerprintMsg{username: e.Username, fingerprint: e.Fingerprint}
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
