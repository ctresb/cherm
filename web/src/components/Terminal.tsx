import { Spinner } from './Spinner';

// Mirrors the real `curl … | bash` install.sh output (deploy/installers/install.sh):
// detect platform → read version.json → download cherm-client-<os>-<arch>.tar.gz →
// verify SHA-256 (script prints the first 16 hex + …) → install cherm + cherm-core
// into ~/.local/bin → connect to srv.cherm.chat:9000.
// The one depicted app window with a radius; everything else stays flat.
export function Terminal() {
  return (
    <div
      className="term"
      role="img"
      aria-label="Terminal running the Cherm installer: detect platform macos-arm64, download the client, verify its SHA-256, install into ~/.local/bin, then launch and connect to srv.cherm.chat"
    >
      <div className="term-bar">
        <span className="term-dots" aria-hidden="true">
          <i className="d red" />
          <i className="d yellow" />
          <i className="d green" />
        </span>
        <span className="term-title">cherm · zsh</span>
      </div>
      <div className="term-body" aria-hidden="true">
        <p className="term-cmd">
          <span className="term-prompt">❯</span> curl -fsSL https://cherm.chat/install.sh | bash
        </p>
        <p><span className="t-info">==&gt;</span> platform · macos-arm64</p>
        <p><span className="t-info">==&gt;</span> latest Cherm Client · v0.1.1</p>
        <p><span className="t-info">==&gt;</span> downloading cherm-client-macos-arm64.tar.gz</p>
        <p className="term-progress" aria-hidden="true">
          <span className="dl">
            <span className="dl-track">▱▱▱▱▱▱▱▱▱▱▱▱▱▱</span>
            <span className="dl-fill">▰▰▰▰▰▰▰▰▰▰▰▰▰▰</span>
          </span>
        </p>
        <p><span className="tick">✓</span> verified · sha256 4f3c8a91e2b7d6c0…</p>
        <p><span className="tick">✓</span> installed <span className="t-arrow">→</span> ~/.local/bin/cherm</p>
        <p className="term-run">
          <Spinner /> launching · srv.cherm.chat:9000
        </p>
      </div>
    </div>
  );
}
