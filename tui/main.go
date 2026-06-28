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
	// CLI flags handled before launching the TUI.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--update", "update":
			force := false
			for _, a := range os.Args[2:] {
				if a == "--force" || a == "-f" {
					force = true
				}
			}
			os.Exit(runUpdateCLI(force))
		case "--version", "-v", "version":
			fmt.Printf("cherm %s\n", clientVersion)
			os.Exit(0)
		case "--help", "-h", "help":
			fmt.Printf("cherm %s — terminal chat for cherm.chat\n\n", clientVersion)
			fmt.Println("usage:")
			fmt.Println("  cherm                 launch the TUI")
			fmt.Println("  cherm --update [-f]   check for & install the latest client")
			fmt.Println("  cherm --version       print version")
			os.Exit(0)
		}
	}

	core := NewCore()
	model := NewModel(core)

	// AltScreen for a full-screen app; mouse cell-motion enables scroll-wheel
	// scrolling and click-to-select in the chat list.
	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())

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
