import { motion } from 'motion/react';
import { nav } from '../content';

export function Header() {
  return (
    <header className="site-header">
      <a className="brand" href="#top" aria-label="Cherm home">
        <img src="/logo.svg" alt="Cherm" />
      </a>
      <nav aria-label="Primary">
        {nav.map((item) => (
          <a key={item.href} href={item.href}>{item.label}</a>
        ))}
      </nav>
      <motion.a
        className="header-cta"
        href="#install"
        whileHover={{ y: -2 }}
        whileTap={{ scale: 0.96 }}
        transition={{ type: 'spring', stiffness: 420, damping: 22 }}
      >
        Get Cherm
      </motion.a>
    </header>
  );
}
