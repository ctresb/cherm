import { motion } from 'motion/react';
import type { ReactNode } from 'react';

// Text link whose trailing arrow springs to the right on hover/focus.
// The kind of subtle motion the rest of the page leans on.
type Props = { href: string; className?: string; children: ReactNode };

export function ArrowLink({ href, className = '', children }: Props) {
  return (
    <motion.a
      href={href}
      className={`arrow-link ${className}`}
      initial="rest"
      animate="rest"
      whileHover="hover"
      whileFocus="hover"
    >
      <span>{children}</span>
      <motion.span
        className="arrow-glyph"
        aria-hidden="true"
        variants={{ rest: { x: 0 }, hover: { x: 6 } }}
        transition={{ type: 'spring', stiffness: 420, damping: 18 }}
      >
        →
      </motion.span>
    </motion.a>
  );
}
