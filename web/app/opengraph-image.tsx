import { ImageResponse } from "next/og";

// The card a link to the site shows in Devpost, Slack, X or iMessage. Built at build time. Synthetic values only.
export const alt = "MasqAI: your LLM key is a two-way mirror. MasqAI makes it one-way.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

const BG = "#0b0d10";
const CARD = "#12151a";
const BORDER = "#262c35";
const FG = "#e8eaed";
const MUTED = "#a2abb5";
const GREEN = "#4ade80";
const RED = "#ff7b7b";

export default function Image() {
  return new ImageResponse(
    (
      <div style={{ width: "100%", height: "100%", display: "flex", flexDirection: "column", background: BG, padding: "56px 64px", color: FG }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke={GREEN} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M18 11c-1.5 0-2.5.5-3 2" />
            <path d="M4 6a2 2 0 0 0-2 2v4a5 5 0 0 0 5 5 8 8 0 0 1 5 2 8 8 0 0 1 5-2 5 5 0 0 0 5-5V8a2 2 0 0 0-2-2h-3a8 8 0 0 0-5 2 8 8 0 0 0-5-2z" />
            <path d="M6 11c1.5 0 2.5.5 3 2" />
          </svg>
          <span style={{ fontSize: 34, fontWeight: 700 }}>MasqAI</span>
        </div>

        <div style={{ display: "flex", flexDirection: "column", marginTop: 34, fontSize: 64, fontWeight: 700, lineHeight: 1.08, letterSpacing: -1.5 }}>
          <span>Your LLM key is a two-way mirror.</span>
          <span style={{ color: GREEN }}>MasqAI makes it one-way.</span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 22, marginTop: "auto" }}>
          <Pane title="Your machine" color={RED} lines={["sk-or-v1-FAKE5e2b…", "C:\\Users\\alice\\…\\prod.db"]} />
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", border: `2px solid ${GREEN}`, borderRadius: 999, padding: "8px 18px", color: GREEN, fontSize: 22, fontWeight: 700 }}>
            MASQAI →
          </div>
          <Pane title="The untrusted model" color={GREEN} lines={["<OR_KEY_30b6eebf>", "<PATH_b71e04d2>"]} />
        </div>

        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 26, fontSize: 22, color: MUTED }}>
          <span>A local context firewall for AI agents</span>
          <span>masqai.vercel.app · HackHarvard 2026</span>
        </div>
      </div>
    ),
    size,
  );
}

function Pane({ title, color, lines }: { title: string; color: string; lines: string[] }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, background: CARD, border: `1px solid ${BORDER}`, borderRadius: 16, padding: "18px 22px", gap: 10 }}>
      <span style={{ fontSize: 20, color: MUTED }}>{title}</span>
      {lines.map((line) => (
        <span key={line} style={{ display: "flex", fontSize: 26, color, border: `1px solid ${color}55`, background: `${color}1a`, borderRadius: 8, padding: "4px 10px" }}>
          {line}
        </span>
      ))}
    </div>
  );
}
