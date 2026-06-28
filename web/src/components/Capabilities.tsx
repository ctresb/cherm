import { Reveal } from './Reveal';
import { capabilities, features } from '../content';

export function Capabilities() {
  return (
    <section className="section">
      <Reveal className="section-head">
        <p className="eyebrow">What the client owns</p>
        <h2>The work happens on your side of the wire.</h2>
      </Reveal>
      <div className="cap-grid">
        {capabilities.map(([title, body], i) => (
          <Reveal as="article" className="cap" i={i} key={title}>
            <h3>{title}</h3>
            <p>{body}</p>
          </Reveal>
        ))}
      </div>
      <Reveal as="ul" className="feature-strip" aria-label="Also included">
        {features.map((f) => <li key={f}>{f}</li>)}
      </Reveal>
    </section>
  );
}
