import { useEffect, useState } from 'react';

// Quadrant-arc spinner using the glyphs the user asked for. Cycles clockwise.
// Reduced-motion: holds the first frame.
const FRAMES = ['◜', '◝', '◞', '◟'];

export function Spinner() {
  const [i, setI] = useState(0);

  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const id = window.setInterval(() => setI((v) => (v + 1) % FRAMES.length), 110);
    return () => window.clearInterval(id);
  }, []);

  return <span className="spinner" aria-hidden="true">{FRAMES[i]}</span>;
}
