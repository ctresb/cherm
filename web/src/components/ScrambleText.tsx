import { Fragment, useEffect, useState } from 'react';

// "Decryption" reveal: starts as gibberish glyphs and resolves left-to-right to
// the real text once, on mount. Newlines in `text` render as <br>. Honors
// reduced motion (shows the final text immediately).
const GLYPHS = '!<>-_\\/[]{}=+*#%&01ABCDEFXZ?$§¦';

const prefersReduced = () =>
  typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function scrambled(text: string) {
  let s = '';
  for (const ch of text) s += ch === ' ' || ch === '\n' ? ch : GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
  return s;
}

export function ScrambleText({ text }: { text: string }) {
  // first paint is already gibberish, so the reveal reads as a decrypt
  const [out, setOut] = useState(() => (prefersReduced() ? text : scrambled(text)));

  useEffect(() => {
    if (prefersReduced()) {
      setOut(text);
      return;
    }
    const TOTAL = 44; // frames
    let frame = 0;
    const id = window.setInterval(() => {
      frame += 1;
      const revealed = (frame / TOTAL) * text.length;
      let s = '';
      for (let i = 0; i < text.length; i++) {
        const ch = text[i];
        if (ch === '\n' || ch === ' ') s += ch;
        else if (i < revealed) s += ch;
        else s += GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
      }
      setOut(s);
      if (frame >= TOTAL) {
        setOut(text);
        window.clearInterval(id);
      }
    }, 14); // ~0.6s total
    return () => window.clearInterval(id);
  }, [text]);

  return (
    <>
      {out.split('\n').map((line, i) => (
        <Fragment key={i}>
          {i > 0 && <br />}
          {line}
        </Fragment>
      ))}
    </>
  );
}
