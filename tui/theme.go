package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Theme support for the TUI. A theme is a plugin (architecture_specification
// §6.1): the active theme's palette is written by the core to
// ~/.cherm/plugins/active-theme.json, which the TUI reads at startup for the
// first frame and re-applies live on a `theme` event (see events.go / model.go).

// Palette is the set of hex colors the chrome styles are built from.
type Palette struct {
	Magenta string `json:"magenta"`
	Pink    string `json:"pink"`
	Dark    string `json:"dark"`
	White   string `json:"white"`
	Border  string `json:"border"`
	Muted   string `json:"muted"`
	Green   string `json:"green"`
	Yellow  string `json:"yellow"`
	Red     string `json:"red"`
}

// defaultPalette is the built-in magenta→pink accent on a near-black base.
func defaultPalette() Palette {
	return Palette{
		Magenta: "#EE00FF",
		Pink:    "#FF007B",
		Dark:    "#17191D",
		White:   "#FFFFFF",
		Border:  "#3A2E3F",
		Muted:   "#8A8D93",
		Green:   "#2ECC71",
		Yellow:  "#F1C40F",
		Red:     "#E74C3C",
	}
}

// activeThemePath is ~/.cherm/plugins/active-theme.json.
func activeThemePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cherm", "plugins", "active-theme.json")
}

// loadPaletteFromDisk reads the active theme palette, filling any missing field
// from the default so the result is always complete. Falls back entirely to the
// default if no theme is active or the file is unreadable.
func loadPaletteFromDisk() Palette {
	p := defaultPalette()
	path := activeThemePath()
	if path == "" {
		return p
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return p
	}
	mergePalette(&p, data)
	return p
}

// mergePalette overlays any present hex fields from JSON onto p (absent fields
// keep their current/default value).
func mergePalette(p *Palette, data []byte) {
	var in Palette
	if err := json.Unmarshal(data, &in); err != nil {
		return
	}
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&p.Magenta, in.Magenta)
	set(&p.Pink, in.Pink)
	set(&p.Dark, in.Dark)
	set(&p.White, in.White)
	set(&p.Border, in.Border)
	set(&p.Muted, in.Muted)
	set(&p.Green, in.Green)
	set(&p.Yellow, in.Yellow)
	set(&p.Red, in.Red)
}

// paletteFromEvent builds a complete Palette from a `theme` event's raw palette
// map (nil/empty => default, i.e. theme removed → revert).
func paletteFromEvent(raw json.RawMessage) Palette {
	p := defaultPalette()
	if len(raw) == 0 || string(raw) == "null" {
		return p
	}
	mergePalette(&p, raw)
	return p
}
