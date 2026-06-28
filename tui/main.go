// Command cherm is the bubbletea terminal UI for cherm.chat.
//
// It is presentation only: it never touches keys, ciphertext, or the network.
// All crypto, networking and local history live in the cherm-core subprocess,
// which this program drives over stdio NDJSON (see PROTOCOL.md section 4).
package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	core := NewCore()
	model := NewModel(core)

	p := tea.NewProgram(model, tea.WithAltScreen())

	// Wire the program so the core's reader goroutine can deliver events, then
	// start the subprocess. Starting before Run lets us fail loudly (outside the
	// alt screen) if the core binary is missing.
	core.SetProgram(p)
	if err := core.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "cherm: failed to start core: %v\n", err)
		fmt.Fprintf(os.Stderr, "set CHERM_CORE to the cherm-core binary path, or build backend first.\n")
		os.Exit(1)
	}

	if _, err := p.Run(); err != nil {
		core.Stop()
		fmt.Fprintf(os.Stderr, "cherm: %v\n", err)
		os.Exit(1)
	}

	// Safety net: ensure the subprocess is gone even on a clean exit.
	core.Stop()
}
