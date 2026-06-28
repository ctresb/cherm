// All landing copy lives here so the narrative reads top-to-bottom in one place
// and the section components stay structural. Voice: direct, declarative, no hype.

export type OSKind = 'unix' | 'windows';

// Real install entrypoints (deploy/installers/install.sh + install.ps1).
export const INSTALL: Record<OSKind, string> = {
  unix: 'curl -fsSL https://cherm.chat/install.sh | bash',
  windows: 'iex (irm https://cherm.chat/install.ps1)',
};
export const OS_LABEL: Record<OSKind, string> = { unix: 'macOS / Linux', windows: 'Windows' };
export const OS_SIGIL: Record<OSKind, string> = { unix: '$', windows: '>' };

export const REPO_URL = 'https://github.com/ctresb/cherm';

export const nav = [
  { label: 'How it works', href: '#how' },
  { label: 'Trust', href: '#trust' },
  { label: 'Install', href: '#install' },
];

export const proof = [
  'End-to-end encrypted',
  'No passwords',
  'Local vaults',
  'Verifiable builds',
];

// How it works - three steps, the path a message takes.
export const steps: [string, string, string][] = [
  [
    '01',
    'Prove it’s you. No password',
    'Login is challenge-response. Each user-and-server pair gets its own device identity. Nothing to leak, nothing to phish.',
  ],
  [
    '02',
    'Seal it on your machine',
    'DMs use Olm, groups use Megolm, through Matrix’s audited vodozemac. Messages are encrypted before they touch the network.',
  ],
  [
    '03',
    'Relay, don’t store',
    'The server delivers sealed messages to offline devices, then forgets them. It never learns who you are or what you said.',
  ],
];

// Capability grid - what the client actually owns.
export const capabilities: [string, string][] = [
  ['Dumb relay', 'The server moves ciphertext and nothing else. No plaintext, no metadata it doesn’t need to deliver a message.'],
  ['Local encrypted vaults', 'Every server lives in its own SQLCipher vault under ~/.cherm. Your history stays on your machine, sealed at rest.'],
  ['Safety numbers', 'Compare a short code with a contact to catch a relay quietly swapping keys in the middle of a conversation.'],
  ['Verifiable builds', 'Before you connect, Cherm tells you the truth about the server: attested, signed, or unknown. No fake guarantees.'],
];

// Thin secondary feature strip.
export const features = [
  'DMs & groups',
  'Multi-server',
  'Leave notices',
  'Plugin store',
  'Self-host the relay',
  'Signed updates',
];

// Honest attestation model - green / yellow / red.
export const attestation: { tone: 'green' | 'yellow' | 'red'; label: string; body: string }[] = [
  { tone: 'green', label: 'TEE-attested', body: 'Runs in a verified enclave. The build the server claims is the build that’s running, and you can check it.' },
  { tone: 'yellow', label: 'Software-signed', body: 'A signed release with no hardware proof. You trust the operator’s key, not the silicon.' },
  { tone: 'red', label: 'Unsigned', body: 'An unknown build. Cherm connects if you tell it to, and never pretends it’s safe.' },
];
