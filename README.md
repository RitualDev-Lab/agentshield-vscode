# AgentShield for VS Code, Cursor & Windsurf 🛡️

[![Open VSX](https://img.shields.io/badge/Open_VSX-ritualdev--lab-blue.svg?style=for-the-badge&logo=visualstudiocode)](https://open-vsx.org/extension/ritualdev-lab/ritual-agent-defense)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Trust Center](https://img.shields.io/badge/Trust-SIG%20Lite%20%2F%20SOC%202-00F59B?style=for-the-badge)](https://ritualdev.in/trust)
[![Playground](https://img.shields.io/badge/Playground-Live%20Demo-00D4FF?style=for-the-badge)](https://ritualdev.in/playground)

> Zero-leak secret defense, kernel sandboxing, and real-time status bar guardrails for Claude Code, Cursor, Windsurf, GitHub Copilot, and Aider.

---

## ⚡ Features

- **Live Status Bar Guard**: Instant indicator in the bottom IDE bar: `🛡️ AgentShield: Guarded (0 Leaks)` or `⚠️ AgentShield: N Leaks!`.
- **Real-Time Diagnostic Squiggles**: Highlights unmasked API keys (OpenAI, Anthropic, AWS, GitHub, Stripe, Slack) and `/proc/self/environ` reads right as you or your AI agent types.
- **Terminal Interceptor & Gate**: Direct integration with `npx @ritualdev-lab/agentshield ci --enforce` to audit full workspaces.
- **100% Air-Gapped**: Runs completely locally with zero outbound telemetry (`AGENTSHIELD_AIR_GAPPED=1`).

---

## 🚀 Quickstart

1. Install from the [Open VSX Registry](https://open-vsx.org/extension/ritualdev-lab/ritual-agent-defense) or VS Code Marketplace.
2. Open any workspace with autonomous agents.
3. Observe the live status bar indicator in the bottom-right corner.
4. Click the status bar to run workspace audits or test hostile payloads in the [Playground](https://ritualdev.in/playground).

---

## 📄 License

MIT © [RitualDev Studio](https://ritualdev.in)
