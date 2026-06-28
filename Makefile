# cherm.chat — build & run helpers
#
#   make build     build the Rust backend (server + core) and the Go TUI
#   make server    run a relay server on 0.0.0.0:9000
#   make run       run the TUI (it spawns the core, which connects to the server)
#   make test      run the backend unit tests
#   make clean     remove build artifacts

ROOT     := $(shell pwd)
BACKEND  := backend
TUI      := tui
SERVER_ADDR ?= 0.0.0.0:9000
CHERM_SERVER ?= 127.0.0.1:9000

.PHONY: all build backend tui server run test clean

all: build

build: backend tui

backend:
	cd $(BACKEND) && cargo build --release

tui:
	cd $(TUI) && go build -o cherm .

# Run a relay server. It can only see ciphertext, never message content.
server: backend
	cd $(BACKEND) && ./target/release/cherm-server --addr $(SERVER_ADDR) --db cherm-server.db

# Run the terminal UI. It launches the Rust core, which holds all keys.
run: build
	CHERM_CORE=$(ROOT)/$(BACKEND)/target/release/cherm-core \
	CHERM_SERVER=$(CHERM_SERVER) \
	./$(TUI)/cherm

test:
	cd $(BACKEND) && cargo test

clean:
	cd $(BACKEND) && cargo clean
	rm -f $(TUI)/cherm $(TUI)/tui
