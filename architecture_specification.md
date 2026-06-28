# Cherm.chat Product & Architecture Specification

Version: `0.2`
Status: Draft
Scope: Client, server, plugins, wallet, presence, DMs, offline queue, notifications, marketplace, updates, and safety rules.

## 1. Core Philosophy

Cherm.chat is an open, auditable, terminal-native chat ecosystem.

The goal is not to maximize profit. The goal is to build a trustworthy, community-first communication system where users can inspect, modify, self-host, fork, extend, and verify the software they use.

Core principles:

```txt
Open by default.
Auditable by design.
Forkable by philosophy.
Official by verification.
Community-first by intent.
Secure by isolation.
Sustainable through support, not artificial scarcity.
```

Cherm.chat should feel like an open standard with an official trusted implementation.

The official Cherm experience is the reference implementation, not the only possible implementation.

---

# 2. Licensing & Openness

## 2.1 Client

The official Cherm client is open-source.

Anyone can inspect it, modify it, fork it, or build their own client that speaks to Cherm-compatible servers.

Forks of the official client codebase must remain public, open-source, and auditable.

## 2.2 Server

The Cherm server is open-source and self-hostable.

Anyone can run a server.

Anyone can fork or modify the server.

Forks of the official server codebase must remain public, open-source, and auditable.

## 2.3 Plugins

All plugins submitted to the official Cherm Store must be public, open-source, and auditable.

Paid plugins are still public-source.

Payment exists to support creators, provide convenience, fund the ecosystem, and distribute signed/verified packages through the official store.

## 2.4 Recommended License

Recommended license for the official client, server, and official plugin SDK:

```txt
GNU AGPLv3
```

The protocol specification may use a more permissive license so that independent clients and tooling can exist without unnecessary friction.

## 2.5 Brand Separation

The code is open.

The brand is controlled.

Protected official identity includes:

```txt
Cherm
Cherm.chat
Cherm Official
Cherm Store
Cherm Verified
Official Cherm Client
Official Cherm Server
Official badges
Official package signing identity
Official logos and visual identity
```

Forks and alternative clients are allowed, but they cannot pretend to be the official Cherm client, official Cherm server, or official Cherm Store.

---

# 3. Official vs Unofficial

“Official” means verified, signed, public, auditable, and compliant with Cherm project rules.

It does not mean “only allowed.”

A server may choose whether it accepts unofficial clients or only official/verified clients.

A client must clearly show whether a server appears to be official, verified, modified, unknown, or untrusted.

The trust model should be visible to the user, not hidden.

The exact implementation of verification is left to the codebase, but the product requirement is simple:

```txt
Users should be able to know whether they are connected to official, verified, or unknown software.
Servers should be able to define whether unofficial clients are allowed.
Clients should be able to show whether a server is official or not.
```

---

# 4. Cherm.chat Client

## 4.1 Client Requirements

The official client must be:

```txt
open-source
auditable
terminal-native
plugin-capable
wallet-safe
compatible with the official Cherm Store
able to show server trust status
able to show plugin trust status
able to notify users about available updates
```

## 4.2 Alternative Clients

Alternative clients are allowed.

They may support other stores, custom UI, custom features, or different distribution models.

They cannot misuse the Cherm official identity.

If they are forks of the official codebase, they must keep the code public and auditable.

## 4.3 Official Store Restriction

The official Cherm client only uses the official Cherm Store.

External stores are not supported in the official client.

Alternative clients may support external stores.

---

# 5. Cherm.chat Server

## 5.1 Server Requirements

The server must be:

```txt
open-source
auditable
self-hostable
compatible with Cherm clients
able to enforce its client acceptance policy
able to support encrypted offline queues
able to route DM requests
able to route wallet address requests
able to broadcast server announcements from authorized master users
```

## 5.2 Public Forks

Any server fork based on the official Cherm server codebase must remain public and auditable.

## 5.3 Server Trust

The client should make it clear whether a server is official, verified, modified, or unknown.

The exact protocol details should be decided during implementation.

---

# 6. Plugins

## 6.1 Plugin Philosophy

Everything extensible in Cherm is a plugin.

There is no separate theme system.

A theme is a plugin that modifies the visual presentation of the client.

Plugins may extend the TUI, add features, change visual behavior, add integrations, or provide optional user-facing utilities.

## 6.2 Plugin Examples

Plugins may include:

```txt
visual themes
voice chat
screen sharing
URL previews/renderers
radio/music features
clock widgets
status widgets
moderation tools
bots
file previews
accessibility tools
custom TUI panels
custom top-left/top-right UI elements
wallet display helpers
currency conversion helpers
```

## 6.3 Plugin API

Cherm needs a structured Plugin API.

The Plugin API should allow plugins to extend the client without giving them unsafe access to private user data or privileged systems.

The Plugin API should support things like:

```txt
adding TUI widgets
adding status-line elements
adding top-left or top-right UI elements
rendering custom message previews
adding commands
adding safe local-only utilities
adding visual themes
adding optional panels
requesting notifications through the notification core
reading approved non-sensitive wallet data
```

The Plugin API must be permission-based.

Plugins should not get broad access by default.

## 6.4 Plugin Language

Plugins should use a simple, sandboxable language or runtime.

Lua is a good candidate because it is small, embeddable, and commonly used for scripting.

The final choice is implementation-dependent.

The requirement is not “must be Lua.”

The requirement is:

```txt
Plugins must be easy to write.
Plugins must be sandboxed.
Plugins must have clear permissions.
Plugins must not compromise user safety or privacy.
Plugins must not access privileged systems directly.
```

## 6.5 Plugin UI Extensions

Plugins should be able to add controlled UI elements to the TUI.

Examples:

```txt
clock in the top-left
clock in the top-right
network status indicator
custom status bar widget
current song/radio indicator
plugin-provided small panel
message renderer for specific URLs
```

These UI extensions must be bounded by the client.

A plugin should not be able to take over privileged UI surfaces such as wallet confirmation screens, permission prompts, or security warnings.

## 6.6 Plugin Permissions

Plugins must clearly declare what they need.

Permission examples:

```txt
network access
microphone access
camera access
screen capture
local file access
notification requests
message rendering
TUI extension
wallet read access
```

Permissions should be visible before installation.

The user should be able to inspect them later.

## 6.7 Wallet Plugin Permissions

Plugins may only receive simple read-only wallet permissions.

Wallet access must always be read-only.

Plugins must never be able to:

```txt
read seed phrases
read private keys
sign transactions
send transactions
broadcast transactions
modify wallet addresses
change transaction destination
hide fees
hide network information
intercept wallet confirmation
modify wallet confirmation UI
access wallet core
```

Allowed wallet-related plugin use cases:

```txt
showing public wallet status
showing public wallet address when explicitly allowed
showing balances if the user allows it
converting balances to USD or another fiat currency
showing estimated fiat value
displaying read-only wallet widgets in the TUI
```

Wallet read permissions should be granular.

A plugin that only needs price conversion should not receive unnecessary wallet data.

## 6.8 Plugin Store Rule

Every plugin submitted to the official Cherm Store must have public source code.

A plugin can be free or paid.

Paid does not mean closed-source.

Payment means:

```txt
supporting the creator
supporting the project
getting official distribution
getting one-click installation
getting verified package delivery
getting automatic updates
getting convenience
```

## 6.9 Manual Plugin Installation

Users may manually download and install public plugins.

The official store exists for convenience, trust, and creator support, not to artificially block access to code.

## 6.10 Plugin Safety Rules

Plugins must not:

```txt
bypass user permissions
bypass notification settings
access wallet core
spoof wallet confirmation UI
hide telemetry
load hidden remote payloads
obfuscate behavior
impersonate system messages
impersonate official Cherm UI
force DMs
force wallet requests
force sound notifications
```

---

# 7. Official Cherm Store

## 7.1 Store Purpose

The Cherm Store exists to provide:

```txt
plugin discovery
official plugin hosting
paid and free plugin distribution
creator support
one-click installs
signed/verified packages
safe updates
reviewed plugin metadata
ecosystem sustainability
```

## 7.2 Store Fee

Cherm may charge a 5% platform fee on plugin sales.

```txt
Creator share: 95%
Cherm share:   5%
```

The fee sustains the project, infrastructure, hosting, package verification, and ecosystem tooling.

## 7.3 Free and Paid Plugins

Plugin creators decide whether their plugin is free or paid.

Both free and paid plugins must be public and auditable if they are distributed through the official store.

## 7.4 Alternative Stores

The official Cherm client only supports the official Cherm Store.

Alternative clients may support alternative stores.

This is allowed.

They cannot claim to be the official Cherm Store.

---

# 8. Client Updates

## 8.1 Update Notification

The official client should notify users when a new version is available.

Example:

```txt
A new Cherm version is available.
[Update] [Ignore]
```

## 8.2 User Control

Updates should not be silently forced.

The user should be able to:

```txt
update now
ignore for now
view release notes
verify the release
```

## 8.3 Update Trust

Official updates should be signed or otherwise verifiable.

The exact implementation should be decided by the codebase, but the requirement is:

```txt
Users should be able to verify that an update is official.
The client should not install untrusted updates silently.
```

## 8.4 Plugin Updates

Plugins installed through the official Cherm Store should also support update notifications.

The user should be able to review plugin updates before installing them.

---

# 9. Wallet

## 9.1 Wallet Purpose

The Cherm wallet exists only for:

```txt
sending money between users
receiving money from users
buying plugins
supporting creators
```

Cherm must not become a custodial wallet.

## 9.2 Wallet Security

The wallet must be local, encrypted, and user-side.

The server does not store private keys.

Plugins do not access wallet core.

Wallet confirmation screens are privileged and cannot be modified by plugins or themes.

## 9.3 Supported Assets

Initial supported assets:

```txt
BTC
ETH
SOL
USDC
USDT
```

## 9.4 Network Selection

The user chooses the network for each asset during setup.

The setup flow should be generic.

If an asset has one supported network, the user sees one option.

If an asset has multiple supported networks, the user chooses one.

Examples:

```txt
BTC  -> Bitcoin
ETH  -> Ethereum
SOL  -> Solana
USDC -> Ethereum, Solana
USDT -> Ethereum, Solana, others if supported later
```

## 9.5 One Wallet Per Crypto

Cherm allows only one wallet configuration per crypto asset.

For multi-network assets, the active wallet is tied to the selected network.

Example:

```txt
USDC on Solana
```

or:

```txt
USDC on Ethereum
```

## 9.6 Wallet Menu

The wallet menu should show all supported assets and whether they are configured.

Example:

```txt
Wallet
├─ BTC    configured
├─ ETH    not configured
├─ SOL    configured
├─ USDC   not configured
└─ USDT   configured
```

If the asset is not configured, pressing Enter starts the wallet creation flow.

If the asset is configured, pressing Enter opens wallet actions such as receiving, sending, viewing address, deleting wallet, or creating a new one.

## 9.7 Wallet Creation Flow

The wallet creation flow should include:

```txt
choose asset
choose network
create wallet
show recovery phrase
confirm recovery phrase
encrypt locally
save wallet
enable send/receive
```

## 9.8 Wallet Address Requests

The Cherm server does not store a public wallet directory.

Users request wallet addresses directly from other users.

Request all wallets:

```txt
/wallets username
```

Request a specific asset:

```txt
/wallet sol username
/wallet usdc username
/wallet btc username
```

Optional network-specific syntax may exist:

```txt
/wallet usdc:sol username
/wallet usdt:eth username
```

When a user receives a wallet request, the TUI shows:

```txt
{username} is requesting your wallet addresses.
[Allow] [Deny]
```

If allowed, the client sends the approved public address data.

If denied, the requester sees that the request was denied.

If the user has no wallet configured, the requester sees:

```txt
This user doesn't have any wallet.
```

## 9.9 Sending Money in Chat

Public chat syntax:

```txt
$username amount currency
```

Example:

```txt
$joao 20sol
```

Private DM syntax:

```txt
$20sol
```

Sending money must always require confirmation.

Typing a payment command must never send funds immediately.

The confirmation screen must show:

```txt
recipient
asset
network
amount
estimated fee
destination address
confirm/cancel action
```

After sending, the chat may show a system message with transaction status and transaction hash.

Example:

```txt
João sent 20 SOL to @joao
Tx: 5F8x...9Qa
Status: pending
```

Bitcoin and other slow-confirmation networks should show confirmation progress.

---

# 10. Wallet Core Isolation

The wallet core is a privileged system.

It must be isolated from:

```txt
plugins
themes
normal message rendering
server-controlled UI
untrusted client extensions
```

Plugins may request safe wallet UI actions through approved APIs, but they cannot control the transaction flow.

Allowed:

```txt
plugin asks to open a wallet-related view
plugin reads approved read-only wallet data
plugin converts visible wallet values to fiat
plugin displays approved wallet information in a UI widget
```

Not allowed:

```txt
plugin signs transactions
plugin sends funds
plugin reads private keys
plugin reads seed phrases
plugin modifies wallet confirmation UI
plugin modifies destination address
plugin hides fees
plugin controls wallet core
```

---

# 11. Direct Messages

## 11.1 DM Command

Users can request a DM from a public server or group:

```txt
/dm username
```

## 11.2 Consent-Based DMs

The server routes the request.

The receiving client decides based on local user settings.

The server does not force DMs.

The user must be able to prevent unwanted DMs.

## 11.3 DM Privacy Settings

The user should be able to define who can request DMs.

Possible settings:

```txt
allow everyone
allow users from same server
allow contacts/friends only
request approval every time
deny everyone
```

These settings are local.

The client responds based on the user's local rules.

## 11.4 No Forced DMs

It must be impossible to force a DM with a user who does not allow it.

A server may route requests, but the receiving client must enforce the local DM policy.

---

# 12. Local Blocklist & Word Blacklist

## 12.1 Purpose

Users should be able to locally block or auto-ignore unwanted requests based on words, phrases, or patterns.

This is useful for:

```txt
DM spam
wallet request spam
harassment
scams
repeated unwanted phrases
server invite spam
plugin solicitation spam
```

## 12.2 Local-First Rule

The word blacklist is local to the user.

The server does not control it.

The server does not need to know it.

## 12.3 Plain Text Format

The blacklist should be plain text and easy to share.

Words or phrases should be separated by commas.

Example:

```txt
airdrop, free money, seed phrase, double your crypto, urgent payment, click this link
```

## 12.4 Import and Export

Users should be able to:

```txt
export blacklist
import blacklist
share blacklist as plain text
merge imported blacklist with current blacklist
replace current blacklist with imported blacklist
```

## 12.5 Behavior

If a request matches the local blacklist, the client can automatically ignore it.

This can apply to:

```txt
DM requests
wallet address requests
plugin-related requests
unknown-user requests
server-level unsolicited prompts
```

The user should be able to choose whether matches are silently ignored or shown as filtered.

Example local system message:

```txt
*Request ignored by local blacklist.*
```

## 12.6 Safety

The blacklist should never block critical security warnings, wallet confirmations, or official client safety prompts.

---

# 13. Presence Status

## 13.1 Status Values

Cherm uses four status values:

```txt
online
afk
dnd
offline
```

## 13.2 User-Selectable Status

The user can manually select only:

```txt
online
dnd
```

The user cannot manually set:

```txt
afk
offline
```

AFK and offline are automatic.

## 13.3 Status Meaning

```txt
online  = user is connected and available
dnd     = user is connected, but notifications are disabled
afk     = user is connected, status is online, and there has been no input/message for 5 minutes
offline = user is disconnected or has no active session
```

## 13.4 AFK

AFK activates automatically after 5 minutes without input or sent messages.

The user cannot manually set AFK.

## 13.5 DND

DND means “Do Not Disturb.”

When DND is active:

```txt
sound notifications are disabled
desktop notifications are disabled
DM sounds are disabled
mention sounds are disabled
system sounds are disabled
messages still arrive normally
badges may update silently
```

DND has priority over AFK.

If the user is DND and idle, the user remains DND.

## 13.6 Offline

Offline is automatic when the user is disconnected or has no active session.

## 13.7 Status Colors

```txt
online  = green
afk     = yellow
dnd     = red
offline = gray
```

Compact TUI display:

```txt
green  ● = online
yellow ● = afk
red    ● = dnd
gray   ● = offline
```

---

# 14. System Messages

## 14.1 System Message Scopes

Cherm supports system messages with different visibility scopes.

```txt
local   = visible only to one user
dm      = visible inside a DM
group   = visible inside a group
public  = visible publicly
server  = server-level announcement
```

## 14.2 Local System Messages

Local system messages appear only to one user.

They should be faded and italic.

Example:

```txt
*You had 3 new messages, but they expired after 72h.*
```

## 14.3 Public System Messages

Public system messages should use a different color.

They must not look like normal user messages.

Example:

```txt
[SERVER] Maintenance starts in 10 minutes.
```

## 14.4 Server Announcements

Servers may define master users who can send announcements.

Command:

```txt
/announce message
```

Only authorized master users can use this.

Master users should be identified by stable identity, not only by username.

---

# 15. Offline Message Queue

## 15.1 Core Rule

Offline delivery requires storing the message somewhere until the recipient returns.

Cherm accepts this only through an encrypted server-side queue.

## 15.2 Queue Requirements

The offline queue must follow these rules:

```txt
messages are encrypted
server cannot read message contents
maximum queue lifetime is 72h
message is deleted after delivery
message is deleted after expiration
expired content is not recoverable
```

## 15.3 Expiration Notice

If messages expire before delivery, the user may see a local system message.

Example:

```txt
*You had new messages, but they were deleted from the server after 72h.*
```

With count:

```txt
*You had 3 new messages, but they were deleted from the server after 72h.*
```

The notice should not reveal message contents.

## 15.4 Privacy

The server should store the minimum information required to deliver encrypted queued messages and report expiration.

The queue must not become permanent chat history.

---

# 16. Notifications

## 16.1 Notification Types

Cherm supports sound notifications for:

```txt
DMs
group mentions
system messages
```

## 16.2 DM Notifications

DMs may trigger a dedicated DM sound.

This only happens if notifications are enabled and the user is not in DND.

## 16.3 Group Notifications

Group messages do not trigger sounds by default.

Group sounds trigger only for:

```txt
@mentions
system messages
```

Normal group messages should not make sound.

## 16.4 System Notifications

System messages may have a distinct sound.

DND disables system sounds.

## 16.5 DND

DND disables all sounds and desktop notifications.

Messages still arrive.

## 16.6 Plugin Notification Rule

Plugins cannot bypass notification settings.

Plugins may request notifications only through the official notification system.

The user’s local settings always decide whether a notification is shown or played.

---

# 17. Public Chat, Groups, and DMs

## 17.1 Public Servers

Public servers can contain public chats, groups, or channels.

Users can:

```txt
send public messages
mention users
request DMs
request wallet addresses
receive server announcements
interact with plugins
```

## 17.2 Group Mentions

Mention syntax:

```txt
@username
```

Mentions can trigger sound if notifications are enabled and the user is not in DND.

## 17.3 DM Requests

DMs are always request-based unless the user has configured otherwise.

The receiving client enforces the local DM policy.

---

# 18. Business Model

## 18.1 Purpose

Cherm is not built primarily to make money.

The project is sustained through:

```txt
donations
community support
plugin purchases
official store fees
creator support
```

## 18.2 Paid Plugins

Paid plugins remain public-source.

The value of buying through the official store is:

```txt
supporting the creator
supporting Cherm
one-click install
verified package
signed updates
convenience
trust
```

## 18.3 Store Fee

Cherm takes 5% of sales through the official store.

The fee supports infrastructure, package hosting, verification, development, and the project itself.

## 18.4 Narrative

The code is public because trust matters.

Payment is support, not artificial scarcity.

The store exists for convenience, verification, discovery, and sustainability.

---

# 19. Security Model

## 19.1 Main Goals

Cherm must protect:

```txt
wallet keys
wallet confirmation flow
private messages
DM consent
plugin safety
notification control
server trust visibility
client trust visibility
offline queue privacy
```

## 19.2 Threats to Defend Against

Cherm should defend against:

```txt
malicious plugins
fake official servers
fake official clients
wallet phishing
plugin UI spoofing
forced DMs
plaintext offline storage
hidden telemetry
notification spam
scam wallet requests
abusive DM requests
package/source mismatch
```

## 19.3 Initial Non-Goals

Initial versions do not need to guarantee:

```txt
perfect metadata privacy
unforgeable client identity on arbitrary machines
hardware-backed server attestation
offline delivery without any storage
```

## 19.4 Future Trust Improvements

Future versions may support:

```txt
reproducible builds
transparency logs
hardware-backed attestation
stronger package verification
stronger official server verification
```

---

# 20. Recommended Project Documents

The project should include:

```txt
LICENSE
README.md
TRADEMARKS.md
MARKETPLACE_TERMS.md
PLUGIN_POLICY.md
CLIENT_POLICY.md
SERVER_POLICY.md
WALLET_SECURITY.md
PROTOCOL.md
SECURITY.md
CONTRIBUTING.md
GOVERNANCE.md
```

These documents should define rules, not overfit implementation details.

Implementation-specific data structures should be left to the codebase.

---

# 21. Core Commands

## 21.1 Wallet Commands

```txt
/wallets username
/wallet asset username
/wallet asset:network username
```

Examples:

```txt
/wallets joao
/wallet sol joao
/wallet usdc joao
/wallet usdc:sol joao
/wallet usdt:eth joao
```

## 21.2 DM Command

```txt
/dm username
```

## 21.3 Announcement Command

```txt
/announce message
```

Example:

```txt
/announce Server restart in 5 minutes.
```

## 21.4 Payment Syntax

Public chat:

```txt
$username amount currency
```

Example:

```txt
$joao 20sol
```

Private chat:

```txt
$20sol
```

---

# 22. Final Summary

Cherm.chat is an open, auditable, terminal-native chat ecosystem with public clients, public servers, public plugins, a non-custodial encrypted wallet, consent-based DMs, encrypted offline delivery, local blocklists, verified official distribution, plugin-based extensibility, and a community-first marketplace.

Final design summary:

```txt
Client:
open-source, auditable, forkable, official-store-based, update-aware.

Server:
open-source, auditable, self-hostable, able to expose trust state and enforce its own client policy.

Plugins:
everything is a plugin, including themes.
plugins can extend the TUI through a safe Plugin API.
official store plugins must be public and auditable.

Wallet:
local, encrypted, non-custodial, isolated from plugins and server.
plugin wallet permissions are read-only and limited.

DMs:
request-based, client-enforced, impossible to force if denied locally.

Presence:
online, dnd, afk, offline.
only online and dnd are user-selectable.
afk and offline are automatic.

Offline queue:
encrypted server queue, max 72h, delete on delivery, delete on expiration.

System messages:
local messages are faded and italic.
public/server messages use distinct colors.

Notifications:
DM sounds.
group sounds only for @mentions and system messages.
DND disables all notifications.

Blocklist:
local word blacklist, comma-separated plain text, shareable/importable.

Marketplace:
official store supports free and paid public plugins.
Cherm takes 5% on store sales.
payment supports creators and the project, not code scarcity.

Official status:
official means verified, signed, public, auditable, and policy-compliant.
```

Positioning statement:

```txt
Cherm.chat is an open, auditable and community-first chat ecosystem. The client, server and plugins are public by design. Anyone can fork, host, modify and build alternative clients, but the official Cherm experience is built around verified source, signed builds, public plugins, encrypted local wallets, safe extensibility and a marketplace that funds creators while sustaining the project.
```
