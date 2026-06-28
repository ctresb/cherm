import { Terminal } from './Terminal';
import { CommandBox } from './CommandBox';
import { Reveal } from './Reveal';

export function Install() {
  return (
    <section className="section install" id="install">
      <div className="install-bg" aria-hidden="true" />
      <div className="install-inner">
        <Reveal className="install-copy">
          <p className="eyebrow">Install</p>
          <h2>One line. Then it’s yours.</h2>
          <p className="install-lead">
            The installer detects your OS and arch, verifies the published SHA-256
            before it trusts a byte, and drops <code>cherm</code> and{' '}
            <code>cherm-core</code> into <code>~/.local/bin</code>, no root. It never
            touches <code>~/.cherm</code>, so re-running it is just how you upgrade.
          </p>
          <CommandBox />
          <p className="install-note">macOS · Linux · Windows · or build from source.</p>
        </Reveal>
        <Reveal className="term-wrap" i={1}>
          <Terminal />
        </Reveal>
      </div>
    </section>
  );
}
