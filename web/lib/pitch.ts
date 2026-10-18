/**
 * The pitch, as the site walks through it. One source for pitch mode on the laptop (components/site/pitch-mode)
 * and the speakers' phones (/present). Mirrors the team's "MasqAI pitch script" doc: keep both in step.
 */
export type Stop = {
  speaker: "Skyll" | "Matthew" | "Andy" | "Esme";
  title: string;
  href: string;          // where the laptop goes
  anchor?: string;       // section id on that page
  seconds: number;       // planned length
  cues: string[];        // glanceable points, in order
  handoff: string;       // the last line
  lines: string[];       // the full spoken text, for /present
};

export const STOPS: Stop[] = [
  {
    speaker: "Skyll",
    title: "The hook",
    href: "/",
    seconds: 50,
    cues: [
      "An API key is a two-way mirror: the endpoint reads everything",
      "Our key leaked: we saw strangers' machines through it (≈40 keys)",
      "Point left: what agents send · right: what they should",
    ],
    handoff: "That's MasqAI. Matthew?",
    lines: [
      "Everyone treats an API key like a credit card: it bills you. But it's really a two-way mirror. Whoever runs the endpoint behind it — a provider, a cheap reseller, a relay — can read everything your AI agent sends through it.",
      "We know, because it happened to us. One of our keys leaked. Strangers ran their coding agents on it, and through it we could see their machines: OS fingerprints, the path to the database their agent was working on, even chat usernames and emails. From that one key, we saw traces of about forty others.",
      "This is what an agent really sends. This is what it should send. That's MasqAI. Matthew?",
    ],
  },
  {
    speaker: "Matthew",
    title: "Live: it masks as it goes",
    href: "/try",
    seconds: 45,
    cues: [
      "A gateway on your laptop: the agent talks to it, not the provider",
      "Left: a real config · right: what the provider gets",
      "You choose what's secret: emails switch off, no presets",
      "Local read: restored · curl with the key: rejected",
    ],
    handoff: "Here's a full session…",
    lines: [
      "MasqAI is a gateway that runs on your own laptop. Your agent talks to it instead of to the provider.",
      "On the left is a config file our agent just read: a database password, an API key, an email, the machine's name. On the right is what the provider receives: placeholders. The real values never leave the machine.",
      "And you decide what counts as secret. If emails are fine for you, switch them off and they go through as they are. No presets.",
      "The agent still works, because when the model answers with a command, MasqAI swaps the real values back in, locally. A local read: restored. But if a compromised model tries to send our key to its own server: rejected. It gets a harmless echo instead.",
    ],
  },
  {
    speaker: "Matthew",
    title: "A real session",
    href: "/demo",
    seconds: 30,
    cues: [
      "UC2 plays by itself: the model only ever sees a placeholder",
      "It flips to Without MasqAI: the real path goes out",
      "With MasqAI the command still runs on the real file",
    ],
    handoff: "Andy, what's underneath?",
    lines: [
      "Here's a full recorded session. Without MasqAI, the real database path goes out. With it, the model only ever sees a placeholder, and the command still runs on the real file. Andy, what's underneath?",
    ],
  },
  {
    speaker: "Andy",
    title: "Three layers",
    href: "/",
    anchor: "pipeline",
    seconds: 50,
    cues: [
      "Rules: keys, tokens, passwords. Fast, can't be prompt-injected",
      "A local 7B model: names, addresses, intel",
      "Every tool call checked before anything is restored",
      "Fails closed: nothing is ever sent raw",
      "Next: Key Enigma rotates the key (building now)",
    ],
    handoff: "Esme, does it actually work?",
    lines: [
      "Three layers. First, deterministic detectors for keys, tokens and passwords: fast, and they can't be prompt-injected. Second, a security model, a 7-billion-parameter model running locally, that catches what rules can't: people's names, addresses, the intel in an environment dump. Third, a check on every tool call that comes back, before anything is restored.",
      "And it fails closed. If the security model times out, answers nonsense, or its context is too full to trust, the request is blocked. Nothing is ever sent raw.",
      "That protects the context. The key itself is what I'm building next: Key Enigma rotates your provider key on a timer, so a leaked key stops working within minutes. Esme, does it actually work?",
    ],
  },
  {
    speaker: "Esme",
    title: "The proof, and the close",
    href: "/",
    anchor: "daytona",
    seconds: 60,
    cues: [
      "Real agent · 6 tasks · planted secrets · Daytona sandbox per command, network blocked",
      "Without MasqAI: 29 of 30 runs leaked; all 30 tasks still worked: silent",
      "With MasqAI: 0 of 48 runs leaked, 46 of 48 tasks still done (security model: Gemini Flash, remote)",
      "Close: MasqAI protects the context, Daytona contains the actions · scan the QR",
    ],
    handoff: "Thank you.",
    lines: [
      "We measured it with a real AI agent on six coding tasks, each with secrets planted in its files. Every command the agent ran executed in a fresh Daytona sandbox, with its network blocked, deleted afterwards. So even if the model tried something malicious, it couldn't reach the internet.",
      "Without MasqAI, 29 of 30 runs leaked a planted secret to the model. And all 30 tasks still succeeded: the leak is completely silent.",
      "With MasqAI, 0 of 48 runs leaked, and 46 of 48 tasks still succeeded. For this eval the security model was Gemini Flash, run remotely.",
      "MasqAI protects the context. Daytona contains the actions. It runs on your machine, and you can try it right now on our site. Thank you.",
    ],
  },
];

export const TOTAL_SECONDS = STOPS.reduce((n, s) => n + s.seconds, 0);

/** Planned start of each stop, in seconds from the beginning of the pitch. */
export const STARTS = STOPS.reduce<number[]>((acc, s, i) => [...acc, i === 0 ? 0 : acc[i - 1] + STOPS[i - 1].seconds], []);

export const SPEAKER_TONE: Record<Stop["speaker"], string> = {
  Skyll: "bg-ent-user",
  Matthew: "bg-ent-path",
  Andy: "bg-ent-key",
  Esme: "bg-restored",
};

export const clock = (seconds: number) => `${Math.floor(seconds / 60)}:${String(Math.floor(seconds % 60)).padStart(2, "0")}`;
