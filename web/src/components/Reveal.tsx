import { motion, type Variants } from 'motion/react';
import type { ComponentProps, ReactNode } from 'react';

// Scroll-reveal powered by motion.dev. Polymorphic (`as`) so it renders the real
// element - no extra wrapper div that could break grid alignment. Reveals once;
// `i` staggers siblings. Reduced-motion is honored by motion automatically.
const variants: Variants = {
  hidden: { opacity: 0, y: 24 },
  show: { opacity: 1, y: 0 },
};

type Tag = 'div' | 'p' | 'li' | 'ul' | 'ol' | 'article' | 'section' | 'h1' | 'h2' | 'h3';

type RevealProps = ComponentProps<typeof motion.div> & {
  as?: Tag;
  i?: number;
  children?: ReactNode;
};

export function Reveal({ as = 'div', i = 0, children, ...rest }: RevealProps) {
  const M = motion[as] as typeof motion.div;
  return (
    <M
      initial="hidden"
      whileInView="show"
      viewport={{ once: true, margin: '0px 0px -8% 0px' }}
      variants={variants}
      transition={{ duration: 0.6, delay: i * 0.07, ease: [0.2, 0.7, 0.2, 1] }}
      {...rest}
    >
      {children}
    </M>
  );
}
