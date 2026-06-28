import { createContext, useContext } from 'react';
import type { OSKind } from './content';

// Shared install-target so every CommandBox switches together. Detected once,
// then user-overridable via the tabs.
type OSCtx = { os: OSKind; setOS: (o: OSKind) => void };
export const OSContext = createContext<OSCtx>({ os: 'unix', setOS: () => {} });
export const useOS = () => useContext(OSContext);

export function detectOS(): OSKind {
  if (typeof navigator === 'undefined') return 'unix';
  const uaData = (navigator as unknown as { userAgentData?: { platform?: string } }).userAgentData;
  const plat = String(uaData?.platform || navigator.platform || '').toLowerCase();
  const ua = navigator.userAgent.toLowerCase();
  if (plat.includes('win') || ua.includes('windows')) return 'windows';
  return 'unix';
}
