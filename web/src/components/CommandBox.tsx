import { useState } from 'react';
import { motion } from 'motion/react';
import { INSTALL, OS_LABEL, OS_SIGIL, type OSKind } from '../content';
import { useOS } from '../os';

// OS-aware install command with a tab to switch target. The selected OS is
// shared across every CommandBox on the page, and pre-guessed from the browser.
const ORDER: OSKind[] = ['unix', 'windows'];

export function CommandBox() {
  const { os, setOS } = useOS();
  const [copied, setCopied] = useState(false);
  const cmd = INSTALL[os];

  async function copy() {
    try {
      await navigator.clipboard?.writeText(cmd);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="cmd-wrap">
      <div className="cmd-tabs" role="tablist" aria-label="Install target">
        {ORDER.map((k) => (
          <button
            key={k}
            type="button"
            role="tab"
            aria-selected={os === k}
            className="cmd-tab"
            onClick={() => setOS(k)}
          >
            {OS_LABEL[k]}
          </button>
        ))}
      </div>
      <div className="cmd" role="group" aria-label="Install command">
        <code><span className="cmd-sigil" aria-hidden="true">{OS_SIGIL[os]}</span>{cmd}</code>
        <motion.button
          type="button"
          onClick={copy}
          aria-label="Copy install command"
          whileTap={{ scale: 0.94 }}
          transition={{ type: 'spring', stiffness: 500, damping: 20 }}
        >
          {copied ? 'Copied' : 'Copy'}
        </motion.button>
      </div>
    </div>
  );
}
