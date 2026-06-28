import { Reveal } from './Reveal';

// hands.png runs as a full-bleed background band here - the two hands meeting
// over a single point of light read as two people verifying one safety number.
export function Connect() {
  return (
    <section className="connect" aria-label="Verifying identity between two people">
      <div className="connect-bg" aria-hidden="true" />
      <Reveal className="connect-inner">
        <p className="eyebrow">Verify</p>
        <h2>Two people. One number. No one in the middle.</h2>
        <p>
          Read a short safety number aloud, or check it side by side. If it matches,
          no relay swapped a key on you. If it ever changes, Cherm says so, out loud,
          before you trust the next message.
        </p>
      </Reveal>
    </section>
  );
}
