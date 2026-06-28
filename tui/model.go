package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// screen is the top-level view the TUI is showing.
type screen int

const (
	screenOnboard screen = iota // username registration
	screenChat                  // sidebar + messages + input
	screenMenu                  // server / ping / change-server / docs
	screenHelp                  // command + key reference
)

// menuItemCount is the number of selectable rows on the menu screen.
const menuItemCount = 5

const defaultDocs = "https://cherm.chat/docs"

// focusArea is which chat-screen widget receives navigation keys.
type focusArea int

const (
	focusInput focusArea = iota
	focusSidebar
)

const defaultServer = "127.0.0.1:9000"

// chatState holds one chat's metadata plus its locally cached messages.
type chatState struct {
	info     ChatInfo
	messages []Message
	activity bool // unread activity while another chat is open
}

// Model is the bubbletea model for the whole TUI.
type Model struct {
	core       *Core
	serverAddr string

	// window + layout
	width, height int
	sidebarW      int
	contentH      int

	// top-level state
	ready  bool
	screen screen
	focus  focusArea

	// identity / connection state mirrored from core events
	username   string
	uuid       string
	registered bool
	connected  bool

	// onboarding
	nameInput  textinput.Model
	onboardErr string

	// chat screen
	input      textinput.Model
	viewport   viewport.Model
	chats      []*chatState
	chatByID   map[string]*chatState
	sidebarSel int
	current    string // id of the open chat

	// menu screen
	menuSel     int
	menuEditing bool            // editing the server address field
	serverInput textinput.Model // server address editor
	pingMs      int64           // last measured latency, -1 if unknown
	docsURL     string

	// transient footer status
	status  string
	isError bool
}

// NewModel builds the initial model. The core is expected to be started by the
// caller (main) before the program runs; the model drives it via commands and
// reacts to its events.
func NewModel(core *Core) Model {
	name := textinput.New()
	name.Placeholder = "username"
	name.CharLimit = 16
	name.Width = 24
	name.Prompt = "> "
	name.Focus()

	in := textinput.New()
	in.Placeholder = "type a message or /command"
	in.Prompt = "> "
	in.CharLimit = 4096
	in.Width = 40

	server := defaultServer
	if s := envServer(); s != "" {
		server = s
	}

	docs := defaultDocs
	if d := envDocs(); d != "" {
		docs = d
	}

	srv := textinput.New()
	srv.Placeholder = "host:port"
	srv.Prompt = "> "
	srv.CharLimit = 128
	srv.Width = 32

	return Model{
		core:        core,
		serverAddr:  server,
		screen:      screenOnboard,
		focus:       focusInput,
		nameInput:   name,
		input:       in,
		serverInput: srv,
		viewport:    viewport.New(40, 10),
		chatByID:    map[string]*chatState{},
		pingMs:      -1,
		docsURL:     docs,
		status:      "starting cherm-core...",
	}
}

// Init starts the cursor blink. The core was already started by main, so the
// startup flow is driven by the "ready" event handled in Update.
func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

// cmdSend writes a command to the core off the UI goroutine, surfacing any
// write failure as an errorMsg.
func (m Model) cmdSend(cmd map[string]any) tea.Cmd {
	core := m.core
	return func() tea.Msg {
		if err := core.sendCmd(cmd); err != nil {
			return errorMsg{message: "core write failed: " + err.Error()}
		}
		return nil
	}
}

// quitCmd tears down the core and quits the program cleanly.
func (m Model) quitCmd() tea.Cmd {
	m.core.Stop()
	return tea.Quit
}

// Update is the central event loop.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.layout()
		return m, nil

	case tea.KeyMsg:
		// Ctrl+C always exits cleanly, regardless of screen/focus.
		if msg.String() == "ctrl+c" {
			return m, m.quitCmd()
		}
		switch m.screen {
		case screenOnboard:
			return m.updateOnboard(msg)
		case screenMenu:
			return m.updateMenu(msg)
		case screenHelp:
			return m.updateHelp(msg)
		default:
			return m.updateChat(msg)
		}

	// ---- core events ----
	case readyMsg:
		return m.onReady(msg)
	case statusMsg:
		m.connected = msg.connected
		m.registered = msg.registered
		if msg.username != "" {
			m.username = msg.username
		}
		return m, nil
	case registeredMsg:
		m.username = msg.username
		m.uuid = msg.uuid
		m.registered = true
		m.connected = true
		return m.enterChat(), m.afterEnterCmd()
	case connectedMsg:
		m.username = msg.username
		m.uuid = msg.uuid
		m.connected = true
		m.flash(fmt.Sprintf("connected as %s", msg.username), false)
		return m.enterChat(), m.afterEnterCmd()
	case disconnectedMsg:
		m.connected = false
		m.flash("disconnected: "+msg.reason, true)
		return m, nil
	case chatsMsg:
		m.applyChats(msg.chats)
		return m, nil
	case historyMsg:
		return m.onHistory(msg)
	case messageMsg:
		return m.onMessage(msg)
	case errorMsg:
		txt := msg.message
		if msg.code != "" {
			txt = fmt.Sprintf("%s (%s)", msg.message, msg.code)
		}
		m.flash("error: "+txt, true)
		// During onboarding, surface registration errors inline too.
		if m.screen == screenOnboard {
			m.onboardErr = txt
		}
		return m, nil
	case infoMsg:
		m.flash(msg.message, false)
		return m, nil
	case pongMsg:
		m.pingMs = msg.rttMs
		return m, nil
	case coreClosedMsg:
		// The core died; nothing more we can do as a pure front-end.
		return m, tea.Quit
	}

	return m, nil
}

// onReady handles the one-time startup "ready" event: branch to onboarding or,
// if an identity already exists, connect and show the chat screen.
func (m Model) onReady(msg readyMsg) (tea.Model, tea.Cmd) {
	m.ready = true
	m.registered = msg.registered
	m.username = msg.username

	if !msg.registered {
		m.screen = screenOnboard
		m.focus = focusInput
		m.status = "register a username to begin"
		m.nameInput.Focus()
		return m, textinput.Blink
	}

	// Existing identity: authenticate, then show the chat screen.
	m2 := m.enterChat()
	return m2, tea.Batch(
		m.cmdSend(map[string]any{"cmd": "connect", "server": m.serverAddr}),
		textinput.Blink,
	)
}

// enterChat switches to the chat screen and focuses the input box.
func (m Model) enterChat() Model {
	m.screen = screenChat
	m.focus = focusInput
	m.input.Focus()
	m.nameInput.Blur()
	m.onboardErr = ""
	m.layout()
	return m
}

// afterEnterCmd refreshes the chat list once we reach the chat screen.
func (m Model) afterEnterCmd() tea.Cmd {
	return m.cmdSend(map[string]any{"cmd": "list_chats"})
}

// ---- onboarding ----

func (m Model) updateOnboard(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		u := strings.TrimSpace(m.nameInput.Value())
		if !validUsername(u) {
			m.onboardErr = "username must be 1-16 chars, letters and digits only"
			return m, nil
		}
		m.onboardErr = ""
		m.status = "registering " + u + "..."
		return m, m.cmdSend(map[string]any{
			"cmd":      "register",
			"username": u,
			"server":   m.serverAddr,
		})
	}

	var cmd tea.Cmd
	m.nameInput, cmd = m.nameInput.Update(msg)
	return m, cmd
}

// ---- chat screen ----

func (m Model) updateChat(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "tab", "shift+tab":
		m.toggleFocus()
		return m, nil
	}

	if m.focus == focusSidebar {
		switch msg.String() {
		case "up", "k":
			if m.sidebarSel > 0 {
				m.sidebarSel--
			}
			return m, nil
		case "down", "j":
			if m.sidebarSel < len(m.chats)-1 {
				m.sidebarSel++
			}
			return m, nil
		case "enter":
			return m.openSelectedChat()
		case "esc":
			return m.openMenu()
		}
		return m, nil
	}

	// focus == input
	switch msg.String() {
	case "esc":
		return m.openMenu()
	case "enter":
		return m.submitInput()
	case "pgup":
		m.viewport.ViewUp()
		return m, nil
	case "pgdown":
		m.viewport.ViewDown()
		return m, nil
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *Model) toggleFocus() {
	if m.focus == focusInput {
		m.focus = focusSidebar
		m.input.Blur()
	} else {
		m.focus = focusInput
		m.input.Focus()
	}
}

// openSelectedChat opens whatever the sidebar selection points at.
func (m Model) openSelectedChat() (tea.Model, tea.Cmd) {
	if m.sidebarSel < 0 || m.sidebarSel >= len(m.chats) {
		return m, nil
	}
	id := m.chats[m.sidebarSel].info.ID
	cmd := m.openChat(id)
	return m, cmd
}

// openChat marks a chat active, clears its activity flag, refreshes the
// viewport from cache, and asks the core for fresh history.
func (m *Model) openChat(id string) tea.Cmd {
	m.current = id
	if cs := m.chatByID[id]; cs != nil {
		cs.activity = false
	}
	m.refreshViewport()
	return m.cmdSend(map[string]any{"cmd": "history", "chat": id, "limit": 200})
}

// submitInput handles a press of Enter in the input box: slash commands are
// parsed; anything else is sent as a message to the open chat.
func (m Model) submitInput() (tea.Model, tea.Cmd) {
	line := strings.TrimSpace(m.input.Value())
	if line == "" {
		return m, nil
	}
	m.input.Reset()

	if strings.HasPrefix(line, "/") {
		return m.runCommand(line)
	}

	if m.current == "" {
		m.flash("no chat open: use /dm <user> or pick one with Tab", true)
		return m, nil
	}
	return m, m.cmdSend(map[string]any{"cmd": "send", "chat": m.current, "text": line})
}

// runCommand parses and dispatches a slash command typed in the input box.
func (m Model) runCommand(line string) (tea.Model, tea.Cmd) {
	fields := strings.Fields(line)
	cmd := fields[0]
	args := fields[1:]

	switch cmd {
	case "/quit":
		return m, m.quitCmd()

	case "/dm":
		if len(args) != 1 {
			m.flash("usage: /dm <user>", true)
			return m, nil
		}
		if args[0] == m.username {
			m.flash("you can't start a chat with yourself", true)
			return m, nil
		}
		return m, m.cmdSend(map[string]any{"cmd": "start_dm", "username": args[0]})

	case "/group":
		if len(args) < 2 {
			m.flash("usage: /group <name> <member1> <member2> ...", true)
			return m, nil
		}
		return m, m.cmdSend(map[string]any{
			"cmd":     "create_group",
			"name":    args[0],
			"members": args[1:],
		})

	case "/menu":
		return m.openMenu()

	case "/help":
		m.screen = screenHelp
		m.input.Blur()
		return m, nil

	default:
		m.flash("unknown command: "+cmd+" (try /help)", true)
		return m, nil
	}
}

// ---- menu screen ----

// openMenu switches to the menu and refreshes the latency reading.
func (m Model) openMenu() (tea.Model, tea.Cmd) {
	m.screen = screenMenu
	m.menuSel = 0
	m.menuEditing = false
	m.input.Blur()
	m.serverInput.Blur()
	return m, m.cmdSend(map[string]any{"cmd": "ping"})
}

// backToChat returns to the chat screen with the input focused.
func (m Model) backToChat() (tea.Model, tea.Cmd) {
	m.screen = screenChat
	m.focus = focusInput
	m.menuEditing = false
	m.serverInput.Blur()
	m.input.Focus()
	return m, textinput.Blink
}

func (m Model) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Editing the server address field.
	if m.menuEditing {
		switch msg.String() {
		case "enter":
			val := strings.TrimSpace(m.serverInput.Value())
			if val == "" {
				m.flash("server address cannot be empty", true)
				return m, nil
			}
			m.serverAddr = val
			m.menuEditing = false
			m.serverInput.Blur()
			m.pingMs = -1
			m.flash("connecting to "+val+"...", false)
			return m, m.cmdSend(map[string]any{"cmd": "connect", "server": val})
		case "esc":
			m.menuEditing = false
			m.serverInput.Blur()
			return m, nil
		}
		var cmd tea.Cmd
		m.serverInput, cmd = m.serverInput.Update(msg)
		return m, cmd
	}

	switch msg.String() {
	case "esc", "q":
		return m.backToChat()
	case "up", "k":
		if m.menuSel > 0 {
			m.menuSel--
		}
		return m, nil
	case "down", "j":
		if m.menuSel < menuItemCount-1 {
			m.menuSel++
		}
		return m, nil
	case "r":
		return m, m.cmdSend(map[string]any{"cmd": "ping"})
	case "enter":
		return m.activateMenu()
	}
	return m, nil
}

// activateMenu runs the currently highlighted menu item.
func (m Model) activateMenu() (tea.Model, tea.Cmd) {
	switch m.menuSel {
	case 0: // Change server
		m.menuEditing = true
		m.serverInput.SetValue(m.serverAddr)
		m.serverInput.Focus()
		m.serverInput.CursorEnd()
		return m, textinput.Blink
	case 1: // Refresh ping
		return m, m.cmdSend(map[string]any{"cmd": "ping"})
	case 2: // Help
		m.screen = screenHelp
		return m, nil
	case 3: // Open docs
		if err := openBrowser(m.docsURL); err != nil {
			m.flash("could not open browser: "+err.Error(), true)
		} else {
			m.flash("opened docs: "+m.docsURL, false)
		}
		return m, nil
	default: // Back to chat
		return m.backToChat()
	}
}

// ---- help screen ----

func (m Model) updateHelp(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter", "q":
		return m.backToChat()
	}
	return m, nil
}

// ---- core-event helpers ----

// applyChats rebuilds the sidebar from a chats event, preserving any locally
// cached messages / activity flags for chats that still exist.
func (m *Model) applyChats(infos []ChatInfo) {
	list := make([]*chatState, 0, len(infos))
	byID := make(map[string]*chatState, len(infos))
	for _, info := range infos {
		cs := m.chatByID[info.ID]
		if cs == nil {
			cs = &chatState{}
		}
		cs.info = info
		list = append(list, cs)
		byID[info.ID] = cs
	}
	m.chats = list
	m.chatByID = byID

	if m.sidebarSel >= len(m.chats) {
		m.sidebarSel = len(m.chats) - 1
	}
	if m.sidebarSel < 0 {
		m.sidebarSel = 0
	}
}

func (m Model) onHistory(msg historyMsg) (tea.Model, tea.Cmd) {
	cs := m.ensureChat(msg.chat)
	cs.messages = msg.messages
	if msg.chat == m.current {
		m.refreshViewport()
	}
	return m, nil
}

func (m Model) onMessage(msg messageMsg) (tea.Model, tea.Cmd) {
	cs := m.ensureChat(msg.chat)
	cs.messages = append(cs.messages, Message{
		From:     msg.from,
		Text:     msg.text,
		Ts:       msg.ts,
		Outgoing: msg.outgoing,
		Color:    msg.color,
	})
	if msg.ts > cs.info.LastTs {
		cs.info.LastTs = msg.ts
	}

	if msg.chat == m.current {
		m.appendToViewport() // follow the tail only if already at the bottom
	} else {
		cs.activity = true
	}
	return m, nil
}

// ensureChat returns the chat with the given id, creating a placeholder DM
// entry (and sidebar row) if it does not exist yet.
func (m *Model) ensureChat(id string) *chatState {
	if cs := m.chatByID[id]; cs != nil {
		return cs
	}
	cs := &chatState{info: ChatInfo{ID: id, Kind: "dm", Title: id}}
	m.chatByID[id] = cs
	m.chats = append(m.chats, cs)
	return cs
}

// refreshViewport re-renders the open chat into the viewport and scrolls to the
// newest message. Used when explicitly (re)opening a chat or loading history,
// where showing the latest line is always the right thing to do.
func (m *Model) refreshViewport() {
	cs := m.chatByID[m.current]
	if cs == nil {
		m.viewport.SetContent("")
		return
	}
	m.viewport.SetContent(renderMessages(cs.messages))
	m.viewport.GotoBottom()
}

// appendToViewport re-renders the open chat after a new live message arrives.
// It only jumps to the newest line if the reader was already at the bottom; if
// they had scrolled up (pgup) to read older history, their position is kept so
// an incoming message does not yank them away. SetContent preserves YOffset, so
// appended lines leave the visible window unchanged when we do not GotoBottom.
func (m *Model) appendToViewport() {
	cs := m.chatByID[m.current]
	if cs == nil {
		m.viewport.SetContent("")
		return
	}
	atBottom := m.viewport.AtBottom()
	m.viewport.SetContent(renderMessages(cs.messages))
	if atBottom {
		m.viewport.GotoBottom()
	}
}

// flash sets the transient footer status line.
func (m *Model) flash(text string, isErr bool) {
	m.status = text
	m.isError = isErr
}

// layout recomputes widget dimensions from the current window size. Borders add
// 2 to a box's total width/height, so inner content sizes are total - 2.
func (m *Model) layout() {
	if m.width <= 0 || m.height <= 0 {
		return
	}

	const footerH = 2
	const headerH = 1
	sidebarW := 26
	if sidebarW > m.width/3 {
		sidebarW = m.width / 3
	}
	if sidebarW < 14 {
		sidebarW = 14
	}
	if sidebarW > m.width-12 {
		sidebarW = m.width - 12
	}

	contentH := m.height - footerH - headerH
	if contentH < 5 {
		contentH = 5
	}
	mainW := m.width - sidebarW
	if mainW < 12 {
		mainW = 12
	}

	const inputTotalH = 3 // border(2) + 1 line
	vpBoxH := contentH - inputTotalH
	if vpBoxH < 3 {
		vpBoxH = 3
	}

	m.viewport.Width = clampMin(mainW-2, 1)
	m.viewport.Height = clampMin(vpBoxH-2, 1)
	m.input.Width = clampMin(mainW-6, 1)
	m.nameInput.Width = clampMin(min(mainW-6, 40), 1)

	m.sidebarW = sidebarW
	m.contentH = contentH

	m.refreshViewport()
}

// ---- views (see view.go) ----

func (m Model) View() string {
	if !m.ready {
		return lipgloss.NewStyle().Padding(1, 2).Render(m.status)
	}
	switch m.screen {
	case screenOnboard:
		return m.onboardView()
	case screenMenu:
		return m.menuView()
	case screenHelp:
		return m.helpView()
	default:
		return m.chatView()
	}
}
