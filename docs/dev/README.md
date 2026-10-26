# Developer documentation

For people changing the gateway. To use it, read the
[README](../../README.md); every setting is in [CONFIG.md](../CONFIG.md).

| Document | What it is |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the parts fit together. Start here. |
| [MODULES-v3.md](MODULES-v3.md), [modules/](modules/) | The modules and their APIs, kept current with the code. |
| [SPEC-v3.md](SPEC-v3.md) | The v3 build contract. Code comments cite its sections ("SPEC 8"). |
| [PLAN-v4.md](PLAN-v4.md) | The v4 upgrade plan and its requirements matrix; it wins where it differs from SPEC-v3. |
| [FEASIBILITY-v4.md](FEASIBILITY-v4.md) | The platform probes behind PLAN-v4. |
| [PLAN-0.11.md](PLAN-0.11.md) | The 0.11.0 plan: ungated unless configured, per-mode values, the network class, the git stand-in, browser sign-in. It wins where it differs from the documents above; its section 19 (the lead's decisions) wins over its other sections. |
| [DECISIONS.md](DECISIONS.md) | Why it works this way, and what was tried and rejected. Read it before redesigning anything. |
| [TESTING.md](TESTING.md) | How the suite, the mutations, the TUI acceptances and the e2e suite run; coverage per release. |
| [TEST-LOG.md](TEST-LOG.md) | Past test runs and per-phase status notes. |
| [phaseB-requests/](phaseB-requests/) | How the v3 build groups' requests were settled. Design history. |
| [history/](history/) | The v3 plan as approved before the build. Design history. |

The checkpoint contract ([CONTRACT-v1.md](../CONTRACT-v1.md)) and the
capability matrix ([CAPABILITIES.md](../CAPABILITIES.md)) stay in docs/.
Agents working on the repo also read [CLAUDE.md](../../CLAUDE.md).
