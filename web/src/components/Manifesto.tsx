import { Reveal } from './Reveal';

export function Manifesto() {
  return (
    <section className="section manifesto">
      <img className="seal" src="/seal.webp" alt="" aria-hidden="true" width={560} height={560} loading="lazy" />
      <div className="manifesto-inner">
        <Reveal as="p" className="eyebrow">Why it exists</Reveal>
        <Reveal as="h2" i={1}>
          Most “private” chat still asks you to trust the server. Cherm doesn’t.
        </Reveal>
        <Reveal className="manifesto-lines" i={2}>
          <p>The server never holds your keys.</p>
          <p>It never sees your plaintext.</p>
          <p>It moves sealed messages and forgets the rest.</p>
          <p className="accent-line">Trust the math, not the operator.</p>
        </Reveal>
      </div>
    </section>
  );
}
