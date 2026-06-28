package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
)

// Core manages the cherm-core subprocess. The TUI is presentation only: it
// never does crypto or networking. All of that lives behind this stdio bridge.
//
//   - commands (TUI -> core) are written as NDJSON to the core's stdin
//   - events   (core -> TUI) are read   as NDJSON from the core's stdout and
//     delivered to bubbletea via p.Send
//   - stderr is logs; we stash it to a file so it never corrupts the TUI.
type Core struct {
	binPath string

	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr *os.File

	prog *tea.Program // set before Start so the reader can deliver events

	writeMu  sync.Mutex // serializes writes to the core's stdin
	stopOnce sync.Once
}

// hard-coded fallbacks for the core binary, in priority order after $CHERM_CORE.
var coreFallbacks = []string{
	"/Users/joaodavisn/Documents/GitHub/cherm/backend/target/debug/cherm-core",
	"/Users/joaodavisn/Documents/GitHub/cherm/backend/target/release/cherm-core",
}

// NewCore resolves the core binary path but does not start anything yet.
func NewCore() *Core {
	return &Core{binPath: locateCore()}
}

// locateCore finds the cherm-core binary: $CHERM_CORE, then the known debug /
// release build outputs, then "cherm-core" on PATH as a last resort.
func locateCore() string {
	if p := os.Getenv("CHERM_CORE"); p != "" {
		return p
	}
	for _, p := range coreFallbacks {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath("cherm-core"); err == nil {
		return p
	}
	return "cherm-core"
}

// SetProgram wires the bubbletea program so the reader goroutine can deliver
// parsed events. Must be called before Start.
func (c *Core) SetProgram(p *tea.Program) { c.prog = p }

// Start spawns the subprocess, grabs its pipes, and launches the reader
// goroutine. It returns an error if the process cannot be started.
func (c *Core) Start() error {
	c.cmd = exec.Command(c.binPath)

	stdin, err := c.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("core stdin pipe: %w", err)
	}
	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("core stdout pipe: %w", err)
	}
	c.stdin = stdin
	c.stdout = stdout

	// Stash stderr to a log file so core diagnostics never clobber the TUI.
	logPath := filepath.Join(os.TempDir(), "cherm-core.stderr.log")
	if f, ferr := os.Create(logPath); ferr == nil {
		c.stderr = f
		c.cmd.Stderr = f
	}

	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("starting core %q: %w", c.binPath, err)
	}

	go c.readLoop()
	return nil
}

// readLoop scans the core's stdout line by line, parses each JSON event, and
// forwards it to bubbletea. It uses a large buffer because a single history
// event can carry many messages.
func (c *Core) readLoop() {
	scanner := bufio.NewScanner(c.stdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if msg := parseEvent(line); msg != nil && c.prog != nil {
			c.prog.Send(msg)
		}
	}

	// stdout closed: the core has exited (or errored). Notify the model.
	if c.prog != nil {
		c.prog.Send(coreClosedMsg{err: scanner.Err()})
	}
}

// sendCmd marshals a command map to a single JSON line and writes it to the
// core's stdin. Writes are mutex-guarded so concurrent commands never
// interleave on the pipe.
func (c *Core) sendCmd(cmd map[string]any) error {
	b, err := json.Marshal(cmd)
	if err != nil {
		return err
	}
	b = append(b, '\n')

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.stdin == nil {
		return fmt.Errorf("core not started")
	}
	_, err = c.stdin.Write(b)
	return err
}

// Stop tells the core to quit, closes its stdin, and kills the process. It is
// safe to call multiple times.
func (c *Core) Stop() {
	c.stopOnce.Do(func() {
		// Best-effort graceful quit, then tear down regardless.
		_ = c.sendCmd(map[string]any{"cmd": "quit"})
		if c.stdin != nil {
			_ = c.stdin.Close()
		}
		if c.cmd != nil && c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
		if c.stderr != nil {
			_ = c.stderr.Close()
		}
	})
}
