package main

import "encoding/json"

// Widget is one declarative TUI widget contributed by an active plugin
// (architecture_specification §6.5). The client renders only slots/kinds it
// knows; anything else is ignored (bounded by the client).
type Widget struct {
	Slot   string `json:"slot"` // top_left | top_right | status
	Kind   string `json:"kind"` // clock | text
	Value  string `json:"value,omitempty"`
	Format string `json:"format,omitempty"` // Go time layout for kind=clock
}

// PluginPerm is one declared permission plus its human explanation, shown before
// install (architecture_specification §6.6).
type PluginPerm struct {
	ID   string `json:"id"`
	Help string `json:"help"`
}

// StorePlugin is one entry in the plugin store / installed list.
type StorePlugin struct {
	Name        string       `json:"name"`
	DisplayName string       `json:"display_name"`
	Version     string       `json:"version"`
	Kind        string       `json:"kind"`
	Category    string       `json:"category"` // official|community_audited|community_unaudited
	Description string       `json:"description"`
	Author      string       `json:"author"`
	License     string       `json:"license"`
	SourceURL   string       `json:"source_url"`
	Permissions []PluginPerm `json:"permissions"`
	Installed   bool         `json:"installed"`
	Active      bool         `json:"active"`
}

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
	Addr     string `json:"addr"`    // host:port used for connections (internal)
	Name     string `json:"name"`    // user-defined display label (shown in the list)
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
	Color    string `json:"color,omitempty"`  // reserved for premium; "" => white
	System   bool   `json:"system,omitempty"` // a "✣ System" event (e.g. a leave notice)
}

// --- typed tea.Msg values delivered to the model ---

type readyMsg struct {
	servers       []ServerInfo
	hasMaster     bool
	clientVersion string
}

// --- plugin / theme / update / maintenance messages ---

type themeMsg struct {
	palette json.RawMessage // null/empty => revert to default
}

type widgetsMsg struct {
	widgets []Widget
}

type storePluginsMsg struct {
	plugins []StorePlugin
}

type installedPluginsMsg struct {
	plugins []StorePlugin
}

type pluginInstalledMsg struct {
	name     string
	version  string
	category string
}

type pluginUpdateMsg struct {
	name     string
	current  string
	latest   string
	category string
}

type pluginSubmittedMsg struct {
	name    string
	version string
}

type clientUpdateMsg struct {
	current  string
	latest   string
	notesURL string
	url      string
	channel  string
}

type maintenanceMsg struct {
	server     string
	reason     string
	deadlineMs int64
	version    string
}

// openChatMsg asks the TUI to open a chat directly (e.g. right after /dm or
// /group), so the user lands in the conversation without picking it from the list.
type openChatMsg struct {
	chat string
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
	Servers       []ServerInfo `json:"servers"`
	HasMaster     bool         `json:"has_master"`
	ClientVersion string       `json:"client_version"`

	// plugins / theme / widgets / updates
	Plugins    []StorePlugin   `json:"plugins"`
	Palette    json.RawMessage `json:"palette"`
	Widgets    []Widget        `json:"widgets"`
	Name       string          `json:"name"`     // plugin name
	Version    string          `json:"version"`  // plugin/server version
	Category   string          `json:"category"` // plugin trust tier
	Current    string          `json:"current"`
	Latest     string          `json:"latest"`
	NotesURL   string          `json:"notes_url"`
	URL        string          `json:"url"`
	Channel    string          `json:"channel"`
	DeadlineMs int64           `json:"deadline_ms"`

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
		return readyMsg{servers: e.Servers, hasMaster: e.HasMaster, clientVersion: e.ClientVersion}
	case "servers":
		return serversMsg{servers: e.Servers}
	case "theme":
		return themeMsg{palette: e.Palette}
	case "widgets":
		return widgetsMsg{widgets: e.Widgets}
	case "store_plugins":
		return storePluginsMsg{plugins: e.Plugins}
	case "installed_plugins":
		return installedPluginsMsg{plugins: e.Plugins}
	case "plugin_installed":
		return pluginInstalledMsg{name: e.Name, version: e.Version, category: e.Category}
	case "plugin_update_available":
		return pluginUpdateMsg{name: e.Name, current: e.Current, latest: e.Latest, category: e.Category}
	case "plugin_submitted":
		return pluginSubmittedMsg{name: e.Name, version: e.Version}
	case "client_update_available":
		return clientUpdateMsg{current: e.Current, latest: e.Latest, notesURL: e.NotesURL, url: e.URL, channel: e.Channel}
	case "maintenance":
		return maintenanceMsg{server: e.Server, reason: e.Reason, deadlineMs: e.DeadlineMs, version: e.Version}
	case "open_chat":
		return openChatMsg{chat: e.Chat}
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
