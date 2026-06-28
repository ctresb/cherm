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

// readLoop reads the core's stdout one NDJSON frame at a time, parses each into
// a typed event, and forwards it to bubbletea. It uses a bufio.Reader (not a
// bufio.Scanner) so a single oversized frame can never crash the reader: a
// Scanner has a fixed token cap and fails the whole stream with ErrTooLong on a
// long line, which would tear down the TUI. ReadBytes grows as needed, and an
// unparseable frame is simply skipped — the loop only stops on a real EOF/error.
func (c *Core) readLoop() {
	reader := bufio.NewReaderSize(c.stdout, 1024*1024)

	for {
		line, err := reader.ReadBytes('\n')

		// A partial trailing line (no newline) can still accompany io.EOF, so
		// process whatever we got before deciding to stop.
		if len(bytes.TrimSpace(line)) > 0 {
			if msg := parseEvent(line); msg != nil && c.prog != nil {
				c.prog.Send(msg)
			}
		}

		if err != nil {
			// stdout closed (io.EOF) or a transport error: the core has exited.
			if c.prog != nil {
				if err == io.EOF {
					c.prog.Send(coreClosedMsg{err: nil})
				} else {
					c.prog.Send(coreClosedMsg{err: err})
				}
			}
			return
		}
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
