import { useState } from 'react';
import { motion, useReducedMotion, useScroll, useTransform } from 'motion/react';
import { OSContext, detectOS } from './os';
import type { OSKind } from './content';
import { Header } from './components/Header';
import { Hero } from './components/Hero';
import { Manifesto } from './components/Manifesto';
import { HowItWorks } from './components/HowItWorks';
import { Install } from './components/Install';
import { Capabilities } from './components/Capabilities';
import { Trust } from './components/Trust';
import { Connect } from './components/Connect';
import { Footer } from './components/Footer';

export function App() {
  // Whole-page texture drifts a little slower than the scroll.
  const reduce = useReducedMotion();
  const { scrollY } = useScroll();
  const textureY = useTransform(scrollY, (v) => (reduce ? 0 : v * 0.04));

  const [os, setOS] = useState<OSKind>(() => detectOS());

  return (
    <OSContext.Provider value={{ os, setOS }}>
      <motion.div className="page-texture" aria-hidden="true" style={{ y: textureY }} />
      <Header />
      <main>
        <Hero />
        <Manifesto />
        <HowItWorks />
        <Install />
        <Capabilities />
        <Trust />
        <Connect />
      </main>
      <Footer />
    </OSContext.Provider>
  );
}
