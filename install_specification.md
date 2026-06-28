# Cherm.chat Install Specification

Version: `0.1`
Status: Draft
Scope: Client installers, server installers, releases, updates, verification, alternative clients, server runtime, server updates, and deployment modes.

## 1. Purpose

This document defines how Cherm.chat clients and servers should be distributed, installed, verified, updated, and operated.

The goal is to support a simple official installation flow such as:

```sh
curl -fsSL https://cherm.chat/install.sh | bash
```

```powershell
iex (irm https://cherm.chat/install.ps1)
```

And equivalent alternative client installers such as:

```sh
curl -fsSL https://alternativeclient.com/install.sh | bash
```

The install system must support:

```txt
official Cherm client installs
alternative client installs
official Cherm server installs
self-hosted server installs
safe updates
signed or verified releases
clear source/codebase metadata
simple server operation
production-friendly service mode
```

The installer must be convenient, but the user should always have an auditable path.

---

# 2. Distribution Philosophy

Cherm software should be easy to install but not opaque.

The installer should:

```txt
download the correct binary for the user's platform
verify the downloaded artifact
install it into a predictable location
expose version and verification details
avoid silent unsafe behavior
provide an audit-friendly manual path
```

The install flow should not require users to clone the repository or build from source for normal use.

However, because Cherm is open and auditable, every installable artifact should be traceable back to public source code, release metadata, and a specific version.

---

# 3. Installer Types

Cherm should provide separate installers for client and server.

## 3.1 Client Installer

Official client installer URLs:

```txt
https://cherm.chat/install.sh
https://cherm.chat/install.ps1
```

Purpose:

```txt
install the Cherm client application
install the official binary for the current OS/architecture
verify the downloaded artifact
add the client to PATH when appropriate
show installed version
notify the user of successful installation
```

## 3.2 Server Installer

Official server installer URLs:

```txt
https://cherm.chat/server-install.sh
https://cherm.chat/server-install.ps1
```

Purpose:

```txt
install the Cherm server binary
create required server directories
create or initialize server configuration
install helper scripts or service commands
optionally install a system service
prepare the server for long-running operation
print the server address, config path, and next steps
```

## 3.3 Alternative Client Installers

Alternative clients may publish their own installers.

Example:

```txt
https://alternativeclient.com/install.sh
https://alternativeclient.com/install.ps1
```

Alternative client installers should follow the same general expectations:

```txt
clear product identity
public source/codebase metadata
artifact verification
predictable install path
safe update behavior
no false claim of being official Cherm
```

Alternative clients must not claim to be the official Cherm client unless authorized by the Cherm project.

---

# 4. Supported Platforms

The install system should support, at minimum:

```txt
Linux x64
Linux arm64
macOS arm64
macOS x64
Windows x64
```

Additional platforms may be added later.

The installer must detect:

```txt
operating system
CPU architecture
available shell/runtime
installation permissions
existing installation
```

Unsupported systems should fail clearly with a useful error.

---

# 5. Release Artifacts

Cherm releases should publish separate artifacts for client and server.

## 5.1 Client Artifacts

Expected client artifacts:

```txt
cherm-client-linux-x64
cherm-client-linux-arm64
cherm-client-macos-arm64
cherm-client-macos-x64
cherm-client-windows-x64.exe
```

Archives may be used instead of raw binaries when needed.

## 5.2 Server Artifacts

Expected server artifacts:

```txt
cherm-server-linux-x64
cherm-server-linux-arm64
cherm-server-macos-arm64
cherm-server-macos-x64
cherm-server-windows-x64.exe
```

Linux should be the primary production server target.

Windows and macOS server builds may exist for development, testing, or small deployments.

## 5.3 Release Metadata

Each release should include metadata that allows the installer and user to understand:

```txt
version
release channel
artifact names
supported platforms
artifact checksums
source repository
source commit
release notes
signature or verification data
```

The exact metadata format is implementation-defined, but it should be machine-readable.

## 5.4 Checksums

Every release artifact must have a checksum.

SHA-256 is the minimum expected checksum algorithm.

Checksums should be published alongside the artifacts.

## 5.5 Signatures

Official releases should be signed or otherwise verifiable.

At minimum:

```txt
artifact checksum verification is required
official release signature verification is strongly recommended
```

The installer must fail if verification fails.

---

# 6. Installer Security Requirements

## 6.1 Verification

Installers must verify the downloaded binary or archive before installing it.

Verification should include:

```txt
checksum validation
signature validation when available
artifact name/platform validation
version metadata validation when available
```

If verification fails, installation must stop.

## 6.2 No Silent Downgrade

The installer should not silently downgrade an existing installation.

If the installed version is newer than the release being installed, the installer should warn the user.

## 6.3 No Silent Replacement of Config

Installers must not overwrite existing user or server configuration without confirmation or backup.

Server configuration is especially important and should be preserved across updates.

## 6.4 Audit-Friendly Install Path

For users who do not want to pipe directly into a shell, the website should document the manual path:

```sh
curl -fsSL https://cherm.chat/install.sh -o install.sh
cat install.sh
bash install.sh
```

For server:

```sh
curl -fsSL https://cherm.chat/server-install.sh -o server-install.sh
cat server-install.sh
bash server-install.sh
```

The direct pipe install exists for convenience, not as the only supported method.

---

# 7. Client Installation Behavior

## 7.1 Install Command

Official Linux/macOS command:

```sh
curl -fsSL https://cherm.chat/install.sh | bash
```

Official Windows command:

```powershell
iex (irm https://cherm.chat/install.ps1)
```

## 7.2 Client Install Steps

The client installer should:

```txt
detect OS and architecture
select the correct client artifact
download the artifact
download release verification metadata
verify the artifact
install the binary
make it executable when applicable
add it to PATH when appropriate
print installed version
print install location
```

## 7.3 Client Install Location

Default user-level install locations should avoid requiring root/admin permissions.

Recommended defaults:

```txt
Linux/macOS: user-local binary directory
Windows: user-local application directory
```

The installer may support a custom install directory through an environment variable or explicit option.

## 7.4 Client Post-Install Output

After installation, the client installer should print:

```txt
installed version
install path
how to run Cherm
whether the binary was verified
whether PATH was updated
next command to start
```

Example:

```txt
Cherm Client installed.

Version: v0.1.0
Path: ~/.local/bin/cherm
Verification: passed

Run:
  cherm
```

---

# 8. Client Updates

## 8.1 Update Detection

The client should be able to detect when a new version is available.

The client may show:

```txt
A new Cherm version is available.
[Update] [Ignore]
```

## 8.2 User Control

Updates must not be silently forced.

The user should be able to:

```txt
update now
ignore for now
view release notes
verify update source
```

## 8.3 Update Behavior

When updating, the client should:

```txt
download the correct new artifact
verify it
replace the old binary safely
preserve local config
preserve wallet data
preserve plugins
preserve user settings
```

Wallet data must never be deleted or modified by a normal client update.

## 8.4 Alternative Clients

Alternative clients may implement their own update flow.

They should not use the official Cherm update identity unless they are official.

The user should be able to understand which client they are updating.

---

# 9. Server Installation Behavior

## 9.1 Install Command

Official Linux/macOS command:

```sh
curl -fsSL https://cherm.chat/server-install.sh | bash
```

Official Windows command, if supported:

```powershell
iex (irm https://cherm.chat/server-install.ps1)
```

## 9.2 Server Install Steps

The server installer should:

```txt
detect OS and architecture
select the correct server artifact
download the artifact
download release verification metadata
verify the artifact
install the server binary
create server directories
create initial config if missing
create helper scripts or commands
optionally install a long-running service
print server details and next steps
```

## 9.3 Server Install Location

A production server install should use a stable server directory.

Recommended conceptual layout:

```txt
server binary
server config
server data directory
server logs directory
server backup directory
server helper scripts
```

The exact paths are implementation-defined.

The installer should print the actual paths used.

## 9.4 Server Setup Output

After installation, the installer should print:

```txt
server name
public address if configured
config path
binary path
data path
logs path
service status if applicable
available commands
next steps
```

Example:

```txt
Cherm Server installed.

Config: /path/to/config
Binary: /path/to/cherm-server
Data: /path/to/data
Logs: /path/to/logs

Next steps:
  1. Edit server config
  2. Point DNS to this machine
  3. Open required ports
  4. Start the server
```

---

# 10. Server Configuration

## 10.1 Config File

The server must have a config file.

The config file is the main place where a server owner defines server identity, public address, source metadata, client policy, update policy, and operational settings.

The installer should create an initial config if none exists.

The installer must not overwrite an existing config without confirmation or backup.

## 10.2 Required Config Categories

The server config should support the following categories:

```txt
server identity
network/public address
source/codebase metadata
client acceptance policy
master users
offline queue policy
update policy
data/log paths
```

The exact field names and file format are implementation-defined.

## 10.3 Server Identity

The server owner should be able to configure:

```txt
server display name
public server address
server description or short metadata
```

For the official Cherm server, the public address may be:

```txt
srv.cherm.chat
```

## 10.4 Network/Public Address

The config should distinguish between:

```txt
where the server listens
what address users connect to
```

A server may listen locally or on all interfaces, while users connect through a public domain.

The public address is what clients should display and use.

## 10.5 Source/Codebase Metadata

The server owner should be able to expose public codebase information to users.

This may include:

```txt
server source repository
server release version
server public codebase information
official or fork status
```

This exists so users can inspect what codebase the server claims to run.

## 10.6 Client Acceptance Policy

The server owner should be able to choose whether the server accepts unofficial clients.

The policy should support at least:

```txt
accept unofficial clients
reject unofficial clients
```

The exact verification mechanism should be implemented according to the codebase architecture.

The requirement is:

```txt
A server owner must be able to configure whether unofficial clients are allowed.
```

## 10.7 Master Users

The config should allow the server owner to define master users.

Master users can perform privileged server-level actions, such as announcements.

Master users should be identified by stable identity, not only by username.

## 10.8 Offline Queue

The config should support encrypted offline queue behavior.

Required policy:

```txt
offline messages are encrypted
maximum queue lifetime is 72h
delivered messages are deleted
expired messages are deleted
```

## 10.9 Update Policy

The server config should support update-related settings such as:

```txt
update channel
whether automatic update checks are enabled
maintenance warning duration
```

The server must not update in a way that silently destroys configuration or data.

---

# 11. Running the Server

## 11.1 Development Mode

For simple or development usage, the installer may provide:

```sh
./run-server.sh
```

This should start the server in the foreground and print server details to the console.

## 11.2 Production Mode

For production usage, the server should run as a long-running service.

On Linux, this generally means a system service.

The server should restart automatically if the machine reboots.

The installer should support enabling this when appropriate.

## 11.3 Server Commands

The server installation should expose a clear way to:

```txt
start server
stop server
restart server
check server status
view logs
update server
show version
show config path
```

Whether these are shell scripts, CLI subcommands, or service commands is implementation-defined.

## 11.4 Startup Output

When the server starts, it should print useful operational information:

```txt
server name
server version
public address
listening address
config path
data path
logs path
client acceptance mode
offline queue status
source/codebase metadata if configured
```

The output should be clear enough for a server owner to confirm the server is running correctly.

---

# 12. Server Updates

## 12.1 Update Command

The server installation should provide a way to update the server.

Example:

```sh
./update-server.sh
```

Or an equivalent server command.

## 12.2 Update Flow

The server update flow should:

```txt
check latest available version
download release metadata
download the new server artifact
verify checksum/signature
announce maintenance to connected clients
stop accepting new connections
wait for the warning period
gracefully disconnect active clients
stop the server
preserve config and data
replace the server binary
restart the server
allow clients to reconnect
show update result
```

## 12.3 Maintenance Warning

Before stopping for update, the server must notify connected clients.

Default warning:

```txt
Server will stop in 60s for update.
```

The countdown should be rendered by clients locally.

The server should not spam 60 separate chat messages into history.

The server should send a maintenance/update event with a deadline, and clients should display the countdown.

Example client UI:

```txt
[✣ System] Server will stop in 60s for update.
[✣ System] Server will stop in 59s for update.
[✣ System] Server will stop in 58s for update.
```

This countdown is UI state, not permanent chat history.

## 12.4 Waiting for Server Mode

When the server stops for update, connected clients should enter a waiting state.

Example:

```txt
Server is restarting…
Waiting for server.
Reconnecting…
```

The client should attempt to reconnect automatically.

## 12.5 Server Back Online

When the server comes back online, clients should reconnect and show a system notice.

Example:

```txt
Connected.
Server updated successfully.
```

If the update changed the server version, the client may show the new version.

## 12.6 Failed Update

If the update fails before replacing the binary, the server should continue running whenever possible.

If the update fails after stopping, the update script should attempt a safe rollback or print clear recovery instructions.

The update process must avoid corrupting config or user data.

---

# 13. Docker Deployment

## 13.1 Docker Support

Cherm server may support Docker deployment.

Docker is useful for:

```txt
simple deployment
isolated runtime
repeatable server setup
easier upgrades
portable configuration
```

## 13.2 Docker Is Not TEE

Docker is not a hardware Trusted Execution Environment.

Docker does not prove to remote clients that the operator is running the official code.

Docker is only a deployment and isolation tool.

## 13.3 Docker Configuration

A Docker deployment should still expose:

```txt
server config
server data volume
server logs
public address
update path
source/codebase metadata
```

## 13.4 Docker Update

Docker update behavior should still follow the maintenance warning flow:

```txt
notify clients
enter maintenance countdown
stop accepting new connections
stop old container
start new container
clients reconnect
```

---

# 14. TEE Deployment

## 14.1 TEE Is Optional

TEE deployment is not required for normal self-hosted servers.

A normal self-hosted Cherm server can run on a VPS, dedicated server, local machine, or Docker host.

## 14.2 TEE Purpose

TEE is only needed for stronger guarantees where the server operator should not be able to fake what code is running.

TEE exists for the future “operator cannot spoof this” trust model.

## 14.3 TEE Is Infrastructure-Specific

TEE deployment depends on compatible hardware or cloud infrastructure.

Examples of TEE-style deployment targets may include:

```txt
AWS Nitro Enclaves
AMD SEV-SNP environments
Intel SGX environments
confidential computing platforms
```

The exact TEE implementation is separate from the normal installer.

## 14.4 Server Identity

For normal production, a useful mental model is:

```txt
one public server identity = one server instance
```

Multiple logical servers may be possible, but each public server should have clear identity, config, source metadata, and trust state.

---

# 15. Official Server Example

The official Cherm server may use:

```txt
srv.cherm.chat
```

Expected deployment behavior:

```txt
server installed from official server installer
server config defines official public address
server exposes public source/codebase metadata
server runs continuously as a service
server supports safe update flow
server notifies clients before maintenance
clients enter waiting state during restart
clients reconnect automatically
```

---

# 16. Alternative Clients and Installers

## 16.1 Alternative Installer Compatibility

Alternative clients should be able to publish equivalent installers.

Example:

```sh
curl -fsSL https://alternativeclient.com/install.sh | bash
```

```powershell
iex (irm https://alternativeclient.com/install.ps1)
```

## 16.2 Required Alternative Client Identity

Alternative installers must clearly identify what they install.

They should show:

```txt
client name
client source/codebase
client version
client publisher
install path
verification status
```

## 16.3 No Official Impersonation

Alternative installers must not make the user think they are installing the official Cherm client.

Alternative clients can be compatible with Cherm, but they are not official unless approved.

## 16.4 Alternative Update Channels

Alternative clients should use their own update channels, signing identity, releases, and install URLs.

They should not depend on official Cherm release identity unless they are official builds.

---

# 17. Uninstall Behavior

Installers should provide or document uninstall behavior.

Uninstall should allow users to remove:

```txt
client binary
server binary
service files
helper scripts
```

Uninstall should not delete user data, wallet data, server config, or server data unless the user explicitly asks for a destructive uninstall.

For server uninstall, data deletion must require explicit confirmation.

---

# 18. Files That Must Be Preserved

Updates and normal reinstalls must preserve:

```txt
client user config
client wallet data
client plugin data
server config
server data
server logs unless explicitly rotated
server offline queue state when safe
server identity
```

Any destructive operation must be explicit.

---

# 19. Minimum Acceptance Criteria

## 19.1 Client Installer

The client installer is complete when:

```txt
Linux/macOS install command works
Windows install command works, if Windows is supported
installer detects OS/arch
installer downloads the correct artifact
installer verifies the artifact
installer installs the client
client can run after install
client version is displayed
manual audit install path is documented
```

## 19.2 Server Installer

The server installer is complete when:

```txt
server install command works
installer detects OS/arch
installer downloads the correct server artifact
installer verifies the artifact
installer creates or preserves config
installer creates required directories
server can be started
server can run continuously
server prints useful startup details
server update command exists
```

## 19.3 Server Update

The server update system is complete when:

```txt
server can check for a newer version
server can download and verify the update
connected clients receive maintenance warning
clients show local countdown
server stops gracefully
server binary is replaced
server restarts
clients enter waiting mode and reconnect
config and data are preserved
```

## 19.4 Alternative Client Support

Alternative installer compatibility is complete when:

```txt
a third-party client can provide its own install.sh
a third-party client can provide its own install.ps1
the installer clearly identifies the alternative client
the alternative client does not impersonate official Cherm
the install pattern remains familiar to users
```

---

# 20. Final Summary

Cherm must have separate install systems for client and server.

The client install flow should be simple:

```sh
curl -fsSL https://cherm.chat/install.sh | bash
```

```powershell
iex (irm https://cherm.chat/install.ps1)
```

The server install flow should also be simple:

```sh
curl -fsSL https://cherm.chat/server-install.sh | bash
```

The server installer must prepare a real server environment, not just download a binary.

It should create config, install the server, prepare runtime paths, optionally configure a service, and make it easy to run, update, and inspect.

Server updates must be graceful:

```txt
announce update
show 60s countdown
clients enter waiting mode
server stops
server updates
server restarts
clients reconnect
```

Docker may be supported for normal deployments, but Docker is not TEE.

TEE deployment is a separate advanced deployment mode for stronger trust guarantees.

Alternative clients can publish their own installers using the same pattern, such as:

```sh
curl -fsSL https://alternativeclient.com/install.sh | bash
```

But they must clearly identify themselves and must not impersonate the official Cherm client.

The installation system must be convenient, verifiable, auditable, and safe.
