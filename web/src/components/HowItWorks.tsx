import { Reveal } from './Reveal';
import { steps } from '../content';

export function HowItWorks() {
  return (
    <section className="section" id="how">
      <Reveal className="section-head">
        <p className="eyebrow">How it works</p>
        <h2>One message. Three honest steps.</h2>
      </Reveal>
      <ol className="steps">
        {steps.map(([n, title, body], i) => (
          <Reveal as="li" className="step" i={i} key={n}>
            <span className="step-watermark" aria-hidden="true">{n}</span>
            <span className="step-n">{n}</span>
            <h3>{title}</h3>
            <p>{body}</p>
          </Reveal>
        ))}
      </ol>
    </section>
  );
}
