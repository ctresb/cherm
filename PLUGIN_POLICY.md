# Cherm Plugin Policy

Scope: the official Cherm Store, the plugin format, trust tiers, the permission
model, the submission flow, and the safety rules every plugin must obey. This is
the rules document for [`architecture_specification.md`](architecture_specification.md)
§6, §7 and §10. Implementation lives in `backend/core/src/plugins.rs` (client),
`deploy/worker/cherm-edge.js` (store backend), and the `tui/` store UI.

## 1. Everything is a plugin

There is no separate theme system. **A theme is a plugin** that ships a palette.
Plugins extend the TUI through a bounded, declarative API — they are *data*, not
arbitrary code, so they are sandboxed by construction: a plugin can only express
the safe extensions the client knows how to render, and there is no way in the
format to reach a privileged surface.

A plugin is two public objects:

| object | served at | contents |
|---|---|---|
| **manifest** | `plugins.cherm.chat/{name}/manifest` | metadata: name, version, kind, category, permissions, license, source, `package_sha256` |
| **package**  | `plugins.cherm.chat/{name}/package`  | the declarative payload (theme palette, widgets, …) |

Every version is also addressable at `…/{name}/releases/{version}/{manifest,package}`,
and the whole catalog at `plugins.cherm.chat/index`.

`package_sha256` is the SHA-256 of the package bytes. The client verifies it on
every install and update — a mismatch aborts the install.

### Package shape (declarative)

```json
{
  "theme":   { "magenta": "#E0A3FF", "pink": "#FFB3C7", "dark": "#2A2433", "...": "..." },
  "widgets": [ { "slot": "top_right", "kind": "clock", "format": "15:04:05" } ]
}
```

`kind` ∈ `theme | widget | renderer | command | panel | bundle`. Widget `slot` ∈
`top_left | top_right | status` and `kind` ∈ `clock | text`. The client renders
only the slots/kinds it understands; anything else is ignored.

## 2. Trust tiers

Every store plugin carries a **category**, shown to the user *before* install:

| tier | meaning |
|---|---|
| **Official** | maintained or explicitly approved by Cherm. |
| **Community audited** | a community plugin whose public source + package were reviewed and accepted by Cherm. |
| **Community unaudited** | submitted but not yet reviewed — **use at your own risk**. |

The category is **authoritative from the store**, never client-asserted. A
submission always lands as `community_unaudited`; only Cherm can promote it. The
client shows the tier as a colored badge and surfaces an explicit
*"not reviewed by Cherm — install at your own risk"* warning for unaudited
plugins.

## 3. Open-source rule

Every plugin in the official store must be **public-source and auditable**
(`source_url` is required). Paid plugins are still public-source — payment buys
official distribution, signed/verified packages, one-click install and updates,
and creator support, never code scarcity. Cherm takes a 5% store fee on sales.

## 4. Permission model — deny by default

Plugins declare the permissions they need; the user sees them before install. A
plugin holds **no permissions by default**, and a permission outside the
allow-list is rejected at both install and submission time.

**Allowed permissions** (the complete set):

```
tui.theme  tui.widget  tui.statusbar  tui.panel  tui.renderer  tui.command
notify
wallet.read.status  wallet.read.address  wallet.read.balance  wallet.convert.fiat
```

`notify` requests go **through** the notification core — a plugin can never
bypass the user's notification/DND settings.

### Wallet permissions are read-only and granular

A plugin may receive only the four read-only wallet permissions above, and only
the ones it needs (a price-converter gets `wallet.convert.fiat`, not addresses).
Allowed wallet use cases: show whether a wallet is configured, show an approved
public address, show an approved balance, convert a visible balance to fiat,
render read-only wallet widgets.

A plugin can **never** (these are explicitly rejected, never representable):

```
read seed phrases / private keys
sign / send / broadcast transactions
modify a destination address or hide fees
intercept or modify the wallet confirmation UI
access the wallet core
bypass notification settings
impersonate system or official Cherm UI
```

Enforcement is `validate_permissions()` in `backend/core/src/plugins.rs`
(deny-by-default; forbidden + unknown-`wallet.*` rejected) and mirrored in the
store Worker as defense in depth. The wallet core and confirmation screens are a
privileged surface isolated from all plugins and themes
([architecture_specification.md](architecture_specification.md) §10).

## 5. Submission flow

From the client: `/submit` (or the store screen's `s`). The form collects
name, version, kind, source URL, license, description, and permissions. The
client validates permissions locally, then POSTs `{manifest, package}` to
`plugins.cherm.chat/submit`. The store backend:

1. (optionally) checks a submission token,
2. re-validates permissions (deny-by-default),
3. **forces** `category = community_unaudited`,
4. computes `package_sha256` over the canonical package bytes,
5. stores `{name}/manifest`, `{name}/package`, `{name}/releases/{version}/…` in
   R2, and adds the plugin to the catalog `index`.

The submitter cannot self-declare official/audited status.

## 6. Updates

Installed store plugins support update detection: the client compares each
installed version against the store manifest and surfaces
`update available ↑`. The user chooses whether to update; the new package is
re-verified by SHA-256 before it is applied. See the official `pastel-theme`,
whose v1.0.0 → v1.1.0 update adds a clock widget and exercises this path.

## 7. Manual installation

The store exists for convenience, trust, and creator support — not to block
access to code. Because plugins are public files at stable
`plugins.cherm.chat/{name}/...` paths, a user may always download and inspect a
plugin manually.
