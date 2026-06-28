package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// screen is the top-level view the TUI is showing.
type screen int

const (
	screenServers             screen = iota // home: list of known servers + verdict badges
	screenAddServer                         // textinput host:port -> check_server
	screenVerdict                           // attestation verdict + Cancel/Connect buttons
	screenUsername                          // username registration on a server
	screenChat                              // sidebar + messages + input
	screenMenu                              // server / ping / change-server / docs
	screenHelp                              // command + key reference
	screenLeaveConfirm                      // "Leave this chat?" confirmation
	screenStore                             // plugin store: browse / install / update / submit
	screenSubmit                            // plugin submission form
	screenRemoveServerConfirm               // "Remove this server?" confirmation
)

// menuItemCount is the number of selectable rows on the menu screen.
const menuItemCount = 5

// redCountdownSecs is how long "Connect anyway" stays disabled on a red verdict.
const redCountdownSecs = 10

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

// verdictTickMsg drives the 1-second "Connect anyway" countdown on red verdicts.
type verdictTickMsg struct{}

// verdictTick schedules one countdown tick a second from now.
func verdictTick() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return verdictTickMsg{} })
}

// clockTickMsg fires once a second to refresh clock widgets and the local
// server-maintenance countdown (which is UI state, never stored chat history).
type clockTickMsg struct{}

func clockTick() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return clockTickMsg{} })
}

// reconnectTickMsg drives automatic reconnection while in "waiting for server"
// mode after a maintenance restart (install_specification §12.4).
type reconnectTickMsg struct{}

func reconnectTick() tea.Cmd {
	return tea.Tick(3*time.Second, func(time.Time) tea.Msg { return reconnectTickMsg{} })
}

// Model is the bubbletea model for the whole TUI.
type Model struct {
	core *Core

	// the active server's address (chat scope / commands) and its friendly
	// display name (shown in the header instead of host:port).
	serverAddr string
	serverName string

	// window + layout
	width, height int
	sidebarW      int
	contentH      int

	// top-level state
	ready     bool
	hasMaster bool
	screen    screen
	focus     focusArea

	// identity / connection state mirrored from core events
	username  string
	uuid      string
	connected bool

	// servers home
	servers   []ServerInfo
	serverSel int

	// remove-server confirmation
	removeServerAddr string
	removeSel        int // 0 = Remove, 1 = Cancel (defaults to Cancel)

	// add-server / username flow
	addForm       addServerForm   // address / port / name editor (add server)
	checking      bool            // a check_server is in flight
	pendingServer string          // server awaiting a username (need_username)
	nameInput     textinput.Model // username editor
	onboardErr    string

	// verdict screen
	verdict          attestMsg
	verdictSel       int  // 0 = Cancel, 1 = Connect / Connect anyway
	verdictCountdown int  // seconds remaining before "Connect anyway" enables
	verdictTicking   bool // a countdown tick chain is currently live

	// chat screen
	input        textinput.Model
	viewport     viewport.Model
	chats        []*chatState
	chatByID     map[string]*chatState
	sidebarSel   int
	current      string            // id of the open chat
	fingerprints map[string]string // peer username -> safety number

	// leave-chat confirmation
	leaveChatID    string // chat id pending a leave confirmation
	leaveChatTitle string // its display title
	leaveSel       int    // 0 = Leave, 1 = Cancel (defaults to Cancel)

	// menu screen
	menuSel int
	pingMs  int64 // last measured latency, -1 if unknown
	docsURL string

	// client identity / update state
	clientVersion string
	clientUpdate  *clientUpdateMsg // non-nil while a newer client is available

	// plugin store
	storePlugins  []StorePlugin
	storeSel      int
	storeChecking bool
	pluginUpdates map[string]string // plugin name -> latest version available

	// plugin submission form
	submit submitForm

	// active plugin-provided widgets (declarative; bounded by the client)
	widgets []Widget

	// server maintenance / update countdown (rendered locally, never stored)
	maintenance      *maintenanceMsg
	waitingForServer bool

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

	return Model{
		core:          core,
		serverAddr:    server,
		screen:        screenServers,
		focus:         focusInput,
		nameInput:     name,
		input:         in,
		addForm:       newAddServerForm(),
		viewport:      viewport.New(40, 10),
		chatByID:      map[string]*chatState{},
		fingerprints:  map[string]string{},
		pingMs:        -1,
		docsURL:       docs,
		pluginUpdates: map[string]string{},
		submit:        newSubmitForm(),
		status:        "starting cherm-core...",
	}
}

// Init starts the cursor blink and the one-second clock tick (which refreshes
// clock widgets and any active maintenance countdown). The core was already
// started by main, so the startup flow is driven by the "ready" event.
func (m Model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, clockTick())
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

// selfUpdateMsg is the result of an in-app "Update now".
type selfUpdateMsg struct {
	version string
	err     error
}

// selfUpdateCmd downloads + verifies + installs the latest client off the UI
// goroutine (force: the user explicitly chose to update).
func (m Model) selfUpdateCmd() tea.Cmd {
	return func() tea.Msg {
		v, err := selfUpdate(true)
		return selfUpdateMsg{version: v, err: err}
	}
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
		case screenServers:
			return m.updateServers(msg)
		case screenAddServer:
			return m.updateAddServer(msg)
		case screenVerdict:
			return m.updateVerdict(msg)
		case screenUsername:
			return m.updateUsername(msg)
		case screenMenu:
			return m.updateMenu(msg)
		case screenHelp:
			return m.updateHelp(msg)
		case screenLeaveConfirm:
			return m.updateLeaveConfirm(msg)
		case screenStore:
			return m.updateStore(msg)
		case screenSubmit:
			return m.updateSubmit(msg)
		case screenRemoveServerConfirm:
			return m.updateRemoveServerConfirm(msg)
		default:
			return m.updateChat(msg)
		}

	// ---- core events ----
	case readyMsg:
		return m.onReady(msg)
	case serversMsg:
		return m.onServers(msg)
	case attestMsg:
		return m.onAttest(msg)
	case needUsernameMsg:
		return m.onNeedUsername(msg)
	case registeredMsg:
		return m.onRegistered(msg)
	case connectedMsg:
		return m.onConnected(msg)
	case disconnectedMsg:
		if msg.server == "" || msg.server == m.serverAddr {
			m.connected = false
		}
		// If the server announced maintenance, this disconnect is the update
		// stop: enter "waiting for server" and auto-reconnect (install_spec §12.4).
		if m.maintenance != nil && (msg.server == "" || msg.server == m.serverAddr) {
			if !m.waitingForServer {
				m.waitingForServer = true
				m.flash("server is restarting — waiting for server…", false)
				return m, reconnectTick()
			}
			return m, nil
		}
		m.flash("disconnected: "+msg.reason, true)
		return m, nil
	case chatsMsg:
		m.applyChats(msg.chats)
		return m, nil
	case openChatMsg:
		// Land directly in the conversation (e.g. right after /dm or /group).
		if m.screen != screenChat {
			m.screen = screenChat
			m.focus = focusInput
			m.input.Focus()
		}
		// Keep the sidebar selection in sync with the opened chat.
		for i, cs := range m.chats {
			if cs.info.ID == msg.chat {
				m.sidebarSel = i
				break
			}
		}
		cmd := m.openChat(msg.chat)
		return m, cmd
	case historyMsg:
		return m.onHistory(msg)
	case messageMsg:
		return m.onMessage(msg)
	case fingerprintMsg:
		m.fingerprints[msg.username] = msg.fingerprint
		m.flash(fmt.Sprintf("safety number for %s: %s", msg.username, msg.fingerprint), false)
		return m, nil
	case verdictTickMsg:
		if m.screen == screenVerdict && m.verdictCountdown > 0 {
			m.verdictCountdown--
			if m.verdictCountdown > 0 {
				return m, verdictTick()
			}
		}
		// Either the countdown reached zero or we left the verdict screen: this
		// chain stops here, so clear the flag to let a future red verdict start a
		// fresh one. (tea.Tick chains cannot be cancelled, so we must never run
		// two at once — that would drain the safety countdown at 2x+ speed.)
		m.verdictTicking = false
		return m, nil

	// ---- plugin / theme / widgets / update / maintenance ----
	case themeMsg:
		applyPalette(paletteFromEvent(msg.palette))
		return m, nil
	case widgetsMsg:
		m.widgets = msg.widgets
		return m, nil
	case storePluginsMsg:
		m.storePlugins = msg.plugins
		m.storeChecking = false
		if m.storeSel >= len(m.storePlugins) {
			m.storeSel = len(m.storePlugins) - 1
		}
		if m.storeSel < 0 {
			m.storeSel = 0
		}
		return m, nil
	case installedPluginsMsg:
		// Merge installed/active flags into the store view if we are showing it;
		// otherwise just remember them by replacing the list when store is empty.
		m.mergeInstalled(msg.plugins)
		return m, nil
	case pluginInstalledMsg:
		delete(m.pluginUpdates, msg.name)
		m.flash(fmt.Sprintf("installed %s v%s (%s)", msg.name, msg.version, categoryLabel(msg.category)), false)
		return m, nil
	case pluginUpdateMsg:
		m.pluginUpdates[msg.name] = msg.latest
		m.flash(fmt.Sprintf("update for %s: v%s → v%s", msg.name, msg.current, msg.latest), false)
		return m, nil
	case pluginSubmittedMsg:
		m.flash(fmt.Sprintf("submitted %s v%s — community unaudited (pending review)", msg.name, msg.version), false)
		m.screen = screenStore
		return m, nil
	case clientUpdateMsg:
		cu := msg
		m.clientUpdate = &cu
		m.flash(fmt.Sprintf("a new Cherm client is available: v%s (you have v%s)", msg.latest, msg.current), false)
		return m, nil
	case selfUpdateMsg:
		if msg.err != nil {
			m.flash("update failed: "+msg.err.Error(), true)
			return m, nil
		}
		m.clientUpdate = nil
		m.flash(fmt.Sprintf("updated to v%s — restart cherm to apply (your data is preserved)", msg.version), false)
		return m, nil
	case maintenanceMsg:
		// The perpetual clockTick (started in Init) already drives the per-second
		// re-render of the countdown — do NOT start a second chain here or it
		// would tick at 2x.
		mm := msg
		m.maintenance = &mm
		m.flash(msg.reason, false)
		return m, nil
	case clockTickMsg:
		// Drives clock widgets + the maintenance countdown. If a maintenance
		// deadline has passed, fall into waiting-for-server mode.
		var cmds []tea.Cmd
		if m.maintenance != nil && !m.waitingForServer {
			if remainingSecs(m.maintenance.deadlineMs) <= 0 {
				m.waitingForServer = true
				cmds = append(cmds, reconnectTick())
			}
		}
		cmds = append(cmds, clockTick())
		return m, tea.Batch(cmds...)
	case reconnectTickMsg:
		if m.waitingForServer && !m.connected {
			return m, tea.Batch(
				m.cmdSend(map[string]any{"cmd": "connect", "server": m.serverAddr}),
				reconnectTick(),
			)
		}
		return m, nil

	case errorMsg:
		txt := msg.message
		if msg.code != "" {
			txt = fmt.Sprintf("%s (%s)", msg.message, msg.code)
		}
		m.flash("error: "+txt, true)
		m.checking = false
		// During username registration, surface errors inline too.
		if m.screen == screenUsername {
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

// onReady handles the one-time startup "ready" event: with no known servers go
// straight to add-server, otherwise show the servers home screen.
func (m Model) onReady(msg readyMsg) (tea.Model, tea.Cmd) {
	m.ready = true
	m.hasMaster = msg.hasMaster
	m.servers = msg.servers
	if msg.clientVersion != "" {
		m.clientVersion = msg.clientVersion
	}

	// Automatically check for a newer client on launch; the banner (and
	// /update-now) appear only if one is available.
	checkUpdate := m.cmdSend(map[string]any{"cmd": "check_client_update"})

	if len(m.servers) == 0 {
		mdl, cmd := m.openAddServer()
		return mdl, tea.Batch(cmd, checkUpdate)
	}
	m.screen = screenServers
	m.serverSel = 0
	m.status = "select a server to connect"
	return m, tea.Batch(textinput.Blink, checkUpdate)
}

// onServers refreshes the known-servers list and keeps the selection in range.
func (m Model) onServers(msg serversMsg) (tea.Model, tea.Cmd) {
	m.servers = msg.servers
	if m.serverSel >= len(m.servers) {
		m.serverSel = len(m.servers) - 1
	}
	if m.serverSel < 0 {
		m.serverSel = 0
	}
	for _, s := range m.servers {
		if s.Active {
			m.serverAddr = s.Addr
			m.serverName = s.Name
			if s.Username != "" {
				m.username = s.Username
			}
		}
	}
	return m, nil
}

// onAttest shows the verdict screen for a freshly-checked server, starting the
// 10-second countdown when the verdict is red.
func (m Model) onAttest(msg attestMsg) (tea.Model, tea.Cmd) {
	m.verdict = msg
	m.checking = false
	m.screen = screenVerdict
	if msg.verdict == "red" {
		m.verdictSel = 0 // default to Cancel; Connect anyway is disabled
		m.verdictCountdown = redCountdownSecs
		if m.verdictTicking {
			// A previous countdown chain is still alive (e.g. the user cancelled
			// a red verdict and re-checked another within a second). Reuse it
			// rather than starting a second concurrent chain.
			return m, nil
		}
		m.verdictTicking = true
		return m, verdictTick()
	}
	m.verdictSel = 1 // default to Connect for green/yellow
	m.verdictCountdown = 0
	return m, nil
}

// onNeedUsername opens the username registration screen for a server.
func (m Model) onNeedUsername(msg needUsernameMsg) (tea.Model, tea.Cmd) {
	m.pendingServer = msg.server
	m.checking = false
	m.screen = screenUsername
	m.onboardErr = ""
	m.nameInput.SetValue("")
	m.nameInput.Focus()
	m.flash("create a username for "+msg.server, false)
	return m, textinput.Blink
}

// onRegistered records a new identity and enters the chat screen.
func (m Model) onRegistered(msg registeredMsg) (tea.Model, tea.Cmd) {
	if msg.server != "" && msg.server != m.serverAddr {
		m.resetChats()
		m.serverAddr = msg.server
	}
	m.username = msg.username
	m.uuid = msg.uuid
	m.connected = true
	m.checking = false
	m.flash(fmt.Sprintf("registered as %s on %s", msg.username, m.serverAddr), false)
	return m.enterChat(), m.afterEnterCmd()
}

// onConnected makes a server active and enters the chat screen.
func (m Model) onConnected(msg connectedMsg) (tea.Model, tea.Cmd) {
	if msg.server != "" && msg.server != m.serverAddr {
		m.resetChats()
		m.serverAddr = msg.server
	}
	if msg.username != "" {
		m.username = msg.username
	}
	m.connected = true
	m.checking = false
	who := m.username
	if who == "" {
		who = "-"
	}
	// Returning from a maintenance restart: clear the waiting state and confirm.
	if m.waitingForServer || m.maintenance != nil {
		ver := ""
		if m.maintenance != nil && m.maintenance.version != "" {
			ver = " (now v" + m.maintenance.version + ")"
		}
		m.waitingForServer = false
		m.maintenance = nil
		m.flash("connected — server updated successfully"+ver, false)
		return m.enterChat(), m.afterEnterCmd()
	}
	m.flash(fmt.Sprintf("connected to %s as %s", m.serverAddr, who), false)
	return m.enterChat(), m.afterEnterCmd()
}

// enterChat switches to the chat screen and focuses the input box.
func (m Model) enterChat() Model {
	m.screen = screenChat
	m.focus = focusInput
	m.input.Focus()
	m.nameInput.Blur()
	m.addForm.blurAll()
	m.onboardErr = ""
	m.layout()
	return m
}

// afterEnterCmd refreshes the chat list once we reach the chat screen.
func (m Model) afterEnterCmd() tea.Cmd {
	return m.cmdSend(map[string]any{"cmd": "list_chats"})
}

// resetChats clears the per-server chat cache when the active server changes.
func (m *Model) resetChats() {
	m.chats = nil
	m.chatByID = map[string]*chatState{}
	m.current = ""
	m.sidebarSel = 0
	m.viewport.SetContent("")
}

// ---- servers home ----

func (m Model) updateServers(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.serverSel > 0 {
			m.serverSel--
		}
		return m, nil
	case "down", "j":
		if m.serverSel < len(m.servers)-1 {
			m.serverSel++
		}
		return m, nil
	case "a":
		return m.openAddServer()
	case "x":
		return m.openRemoveServerConfirm()
	case "enter":
		return m.connectSelected()
	case "esc":
		if m.connected {
			return m.enterChat(), textinput.Blink
		}
		return m, nil
	case "q":
		return m, m.quitCmd()
	}
	return m, nil
}

// connectSelected connects to the highlighted server, or just opens the chat
// screen if that server is already the active, connected one.
func (m Model) connectSelected() (tea.Model, tea.Cmd) {
	if m.serverSel < 0 || m.serverSel >= len(m.servers) {
		return m, nil
	}
	s := m.servers[m.serverSel]
	m.serverName = s.Name
	if s.Active && m.connected {
		m.serverAddr = s.Addr
		return m.enterChat(), textinput.Blink
	}
	label := s.Name
	if label == "" {
		label = s.Addr
	}
	m.flash("connecting to "+label+"...", false)
	return m, m.cmdSend(map[string]any{"cmd": "connect", "server": s.Addr})
}

// openAddServer switches to the add-server screen with an empty address / port
// / name form (the official server is already seeded in the list).
func (m Model) openAddServer() (tea.Model, tea.Cmd) {
	m.screen = screenAddServer
	m.checking = false
	m.addForm.reset()
	m.flash("", false)
	return m, textinput.Blink
}

// ---- add server (form in addserver.go) ----

func (m Model) updateAddServer(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.addForm.blurAll()
		m.screen = screenServers
		return m, nil
	case "tab", "down":
		m.addForm.focus(m.addForm.sel + 1)
		return m, nil
	case "shift+tab", "up":
		m.addForm.focus(m.addForm.sel - 1)
		return m, nil
	case "enter":
		// Enter advances through the fields; only submits from the last one.
		if m.addForm.sel < 2 {
			m.addForm.focus(m.addForm.sel + 1)
			return m, nil
		}
		return m.submitAddServer()
	case "ctrl+s":
		return m.submitAddServer()
	}
	var cmd tea.Cmd
	*m.addForm.inputs()[m.addForm.sel], cmd = m.addForm.inputs()[m.addForm.sel].Update(msg)
	return m, cmd
}

// submitAddServer builds host:port from the form, attaches the user's name, and
// asks the core to attest it (which also records the name in the server list).
func (m Model) submitAddServer() (tea.Model, tea.Cmd) {
	addr := combineHostPort(m.addForm.address.Value(), m.addForm.port.Value())
	if addr == "" {
		m.flash("server address cannot be empty", true)
		return m, nil
	}
	name := strings.TrimSpace(m.addForm.name.Value())
	m.checking = true
	label := name
	if label == "" {
		label = addr
	}
	m.flash("checking "+label+"...", false)
	return m, m.cmdSend(map[string]any{"cmd": "check_server", "server": addr, "name": name})
}

// ---- verdict ----

func (m Model) updateVerdict(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "left", "h", "shift+tab":
		m.verdictSel = 0
		return m, nil
	case "right", "l", "tab":
		m.verdictSel = 1
		return m, nil
	case "o":
		return m.openVerdictLink()
	case "esc":
		m.screen = screenServers
		return m, nil
	case "enter":
		return m.activateVerdict()
	}
	return m, nil
}

// activateVerdict runs the focused verdict button.
func (m Model) activateVerdict() (tea.Model, tea.Cmd) {
	if m.verdictSel == 0 { // Cancel
		m.screen = screenServers
		return m, nil
	}
	// Connect / Connect anyway.
	if m.verdict.verdict == "red" && m.verdictCountdown > 0 {
		m.flash(fmt.Sprintf("wait %ds before connecting anyway", m.verdictCountdown), true)
		return m, nil
	}
	addr := m.verdict.server
	m.flash("connecting to "+addr+"...", false)
	return m, m.cmdSend(map[string]any{"cmd": "connect", "server": addr})
}

// openVerdictLink opens the verdict's relevant link: the public codebase for a
// red verdict, otherwise the signatures explainer.
func (m Model) openVerdictLink() (tea.Model, tea.Cmd) {
	url := m.verdict.signaturesURL
	if m.verdict.verdict == "red" {
		url = m.verdict.publicCodebaseURL
	}
	if url == "" {
		m.flash("no link available", true)
		return m, nil
	}
	if err := openBrowser(url); err != nil {
		m.flash("could not open browser: "+err.Error(), true)
	} else {
		m.flash("opened "+url, false)
	}
	return m, nil
}

// ---- username registration ----

func (m Model) updateUsername(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.nameInput.Blur()
		m.screen = screenServers
		return m, nil
	case "enter":
		u := strings.TrimSpace(m.nameInput.Value())
		if !validUsername(u) {
			m.onboardErr = "username must be 1-16 chars, letters and digits only"
			return m, nil
		}
		if isReservedUsername(u) {
			m.onboardErr = "that username is reserved for system use"
			return m, nil
		}
		m.onboardErr = ""
		m.flash("registering "+u+"...", false)
		return m, m.cmdSend(map[string]any{
			"cmd":      "register",
			"server":   m.pendingServer,
			"username": u,
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
		case "x":
			return m.openLeaveConfirm()
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

	case "/servers":
		return m.openServersScreen()

	case "/store", "/plugins":
		return m.openStore()

	case "/submit":
		return m.openSubmit()

	case "/update":
		m.flash("checking for a newer Cherm client…", false)
		return m, m.cmdSend(map[string]any{"cmd": "check_client_update"})

	case "/update-now":
		if m.clientUpdate == nil {
			m.flash("no client update available", true)
			return m, nil
		}
		m.flash("downloading & verifying the update…", false)
		return m, m.selfUpdateCmd()

	case "/update-notes":
		if m.clientUpdate == nil || m.clientUpdate.notesURL == "" {
			m.flash("no release notes available", true)
			return m, nil
		}
		if err := openBrowser(m.clientUpdate.notesURL); err != nil {
			m.flash("could not open browser: "+err.Error(), true)
		} else {
			m.flash("opened release notes", false)
		}
		return m, nil

	case "/update-ignore":
		m.clientUpdate = nil
		m.flash("update notice dismissed", false)
		return m, nil

	case "/export":
		m.flash("exporting your identity backup…", false)
		return m, m.cmdSend(map[string]any{"cmd": "export_identity"})

	case "/import":
		if len(args) != 1 {
			m.flash("usage: /import <path-to-.chermkey-file>", true)
			return m, nil
		}
		m.flash("importing identity from "+args[0]+"…", false)
		return m, m.cmdSend(map[string]any{"cmd": "import_identity", "path": args[0]})

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
	m.input.Blur()
	m.addForm.blurAll()
	return m, m.cmdSend(map[string]any{"cmd": "ping"})
}

// openServersScreen switches to the servers home, selecting the active server.
func (m Model) openServersScreen() (tea.Model, tea.Cmd) {
	m.screen = screenServers
	m.input.Blur()
	m.serverSel = 0
	for i, s := range m.servers {
		if s.Addr == m.serverAddr {
			m.serverSel = i
		}
	}
	return m, m.cmdSend(map[string]any{"cmd": "list_servers"})
}

// backToChat returns to the chat screen with the input focused.
func (m Model) backToChat() (tea.Model, tea.Cmd) {
	m.screen = screenChat
	m.focus = focusInput
	m.addForm.blurAll()
	m.input.Focus()
	return m, textinput.Blink
}

func (m Model) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
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
	case 0: // Change server -> servers home
		return m.openServersScreen()
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
		if m.connected {
			return m.backToChat()
		}
		m.screen = screenServers
		return m, nil
	}
	return m, nil
}

// ---- leave-chat confirmation ----

// openLeaveConfirm starts the "Leave this chat?" flow for the highlighted chat.
// The action only happens after explicit confirmation (default = Cancel).
func (m Model) openLeaveConfirm() (tea.Model, tea.Cmd) {
	if m.sidebarSel < 0 || m.sidebarSel >= len(m.chats) {
		return m, nil
	}
	cs := m.chats[m.sidebarSel]
	m.leaveChatID = cs.info.ID
	m.leaveChatTitle = cs.info.Title
	if m.leaveChatTitle == "" {
		m.leaveChatTitle = cs.info.ID
	}
	m.leaveSel = 1 // default to Cancel — leaving is destructive
	m.screen = screenLeaveConfirm
	return m, nil
}

func (m Model) updateLeaveConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "left", "h", "right", "l", "tab", "shift+tab":
		m.leaveSel = 1 - m.leaveSel
		return m, nil
	case "esc":
		m.screen = screenChat
		return m, nil
	case "enter":
		if m.leaveSel == 0 { // Leave
			id := m.leaveChatID
			m.screen = screenChat
			if id == m.current {
				m.current = ""
				m.viewport.SetContent("")
			}
			m.flash("leaving "+m.leaveChatTitle+"...", false)
			return m, m.cmdSend(map[string]any{"cmd": "leave_chat", "chat": id})
		}
		// Cancel — nothing changes.
		m.screen = screenChat
		return m, nil
	}
	return m, nil
}

// ---- remove-server confirmation ----

// openRemoveServerConfirm starts the "Remove this server?" flow for the
// highlighted server. Removing is destructive (drops the local vault), so it
// only happens after explicit confirmation (default = Cancel).
func (m Model) openRemoveServerConfirm() (tea.Model, tea.Cmd) {
	if m.serverSel < 0 || m.serverSel >= len(m.servers) {
		return m, nil
	}
	m.removeServerAddr = m.servers[m.serverSel].Addr
	m.removeSel = 1 // default to Cancel — removal is destructive
	m.screen = screenRemoveServerConfirm
	return m, nil
}

func (m Model) updateRemoveServerConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "left", "h", "right", "l", "tab", "shift+tab":
		m.removeSel = 1 - m.removeSel
		return m, nil
	case "esc":
		m.screen = screenServers
		return m, nil
	case "enter":
		if m.removeSel == 0 { // Remove
			addr := m.removeServerAddr
			m.screen = screenServers
			m.flash("removing "+addr+"...", false)
			return m, m.cmdSend(map[string]any{"cmd": "remove_server", "server": addr})
		}
		m.screen = screenServers // Cancel
		return m, nil
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
		System:   msg.system,
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

// displayServer returns the active server's friendly name, falling back to its
// host:port address when no name is known.
func (m Model) displayServer() string {
	if m.serverName != "" {
		return m.serverName
	}
	return m.serverAddr
}

// currentFingerprint returns the safety number of the open DM's peer, if known.
func (m Model) currentFingerprint() string {
	cs := m.chatByID[m.current]
	if cs == nil || cs.info.Kind != "dm" {
		return ""
	}
	peer := cs.info.Title
	if peer == "" {
		peer = cs.info.ID
	}
	return m.fingerprints[peer]
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
	case screenServers:
		return m.serversView()
	case screenAddServer:
		return m.addServerView()
	case screenVerdict:
		return m.verdictView()
	case screenUsername:
		return m.usernameView()
	case screenMenu:
		return m.menuView()
	case screenHelp:
		return m.helpView()
	case screenLeaveConfirm:
		return m.leaveConfirmView()
	case screenStore:
		return m.storeView()
	case screenSubmit:
		return m.submitView()
	case screenRemoveServerConfirm:
		return m.removeServerConfirmView()
	default:
		return m.chatView()
	}
}
