import { useRef } from 'react';
import { motion, useReducedMotion, useScroll, useSpring, useTransform } from 'motion/react';
import { CommandBox } from './CommandBox';
import { Reveal } from './Reveal';
import { ArrowLink } from './ArrowLink';
import { ScrambleText } from './ScrambleText';
import { proof } from '../content';

export function Hero() {
  const ref = useRef<HTMLElement>(null);
  const reduce = useReducedMotion();
  // Scroll progress across the hero. Spring-smoothed so the parallax never snaps.
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start start', 'end start'] });
  const p = useSpring(scrollYProgress, { stiffness: 140, damping: 30, mass: 0.3 });

  // bg leads (drifts up faster); text lags and fades - depth between the layers.
  // Zeroed out when the user prefers reduced motion.
  const bgY = useTransform(p, [0, 1], [0, reduce ? 0 : -130]);
  const textY = useTransform(p, [0, 1], [0, reduce ? 0 : 96]);
  const textOpacity = useTransform(p, [0, 0.85], [1, reduce ? 1 : 0]);

  return (
    <section className="hero" id="top" ref={ref}>
      {/* hero.png as the section background; scrim keeps text legible */}
      <motion.div className="hero-bg" aria-hidden="true" style={{ y: bgY, scale: 1.2 }} />
      <motion.div className="hero-inner" style={{ y: textY, opacity: textOpacity }}>
        <Reveal as="p" className="eyebrow">Private terminal chat · End-to-end encrypted</Reveal>
        <Reveal as="h1" i={1}>
          <ScrambleText text={'Encrypted before it\never leaves your terminal.'} />
        </Reveal>
        <Reveal as="p" className="lead" i={2}>
          Cherm is a private chat that runs where you work. The client owns identity,
          sessions, and message crypto. The relay only moves ciphertext, and keeps
          nothing it can read.
        </Reveal>
        <Reveal className="hero-actions" i={3}>
          <CommandBox />
          <ArrowLink href="#how">How it works</ArrowLink>
        </Reveal>
        <Reveal as="ul" className="proof-row" i={4} aria-label="What you get">
          {proof.map((item) => <li key={item}>{item}</li>)}
        </Reveal>
      </motion.div>
    </section>
  );
}
