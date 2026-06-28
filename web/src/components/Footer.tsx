import { CommandBox } from './CommandBox';
import { Reveal } from './Reveal';
import { REPO_URL } from '../content';

export function Footer() {
  return (
    <footer className="site-footer">
      <Reveal className="footer-cta">
        <h2>Start the relay you can verify.</h2>
        <CommandBox />
      </Reveal>
      <div className="footer-meta">
        <img className="footer-logo" src="/logo.svg" alt="Cherm" />
        <nav className="footer-links" aria-label="Footer">
          <a href={REPO_URL}>Source</a>
          <a href="https://cherm.chat/install.sh">install.sh</a>
          <a href="#how">How it works</a>
          <a href="#trust">Trust</a>
        </nav>
        <p className="footer-note">The server relays ciphertext. Nothing else.</p>
      </div>
      <div className="footer-badge">
        <a href="https://feitonobrasil.dev.br" target="_blank" rel="noreferrer">
          <img
            src="https://selo.feitonobrasil.dev.br/en/serio/custom/1x.svg?color=%23ffffff"
            alt="Made in Brazil"
            height={56}
            loading="lazy"
          />
        </a>
      </div>
    </footer>
  );
}
