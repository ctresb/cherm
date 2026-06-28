import { Reveal } from './Reveal';
import { attestation } from '../content';

export function Trust() {
  return (
    <section className="section trust" id="trust">
      <Reveal className="section-head">
        <p className="eyebrow">Trust</p>
        <h2>Honest about what it can prove.</h2>
        <p className="section-sub">
          Anyone can run a Cherm relay. Before you connect, the client shows you exactly
          how much that server has earned: green, yellow, or red. No theatre.
        </p>
      </Reveal>
      <ul className="attest">
        {attestation.map((row, i) => (
          <Reveal as="li" className={`attest-row ${row.tone}`} i={i} key={row.label}>
            <span className="attest-dot" aria-hidden="true" />
            <span className="attest-label">{row.label}</span>
            <p className="attest-body">{row.body}</p>
          </Reveal>
        ))}
      </ul>
    </section>
  );
}
