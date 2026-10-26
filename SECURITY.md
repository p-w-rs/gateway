# Security policy

## Supported versions

Only the latest release gets security fixes. Before you report, check that
you run it: `/gate-doctor` shows the version, and [CHANGELOG.md](CHANGELOG.md)
lists the releases.

## Reporting a vulnerability

Report it privately through GitHub: open
https://github.com/p-w-rs/gateway, go to the **Security** tab and choose
**Report a vulnerability**.

If that button is missing, open an issue that asks for a private contact
and gives no details of the problem.

Please don't report it in a public issue, pull request or discussion.

A useful report has:

- the gateway version, the Claude Code version and your OS;
- what you did, what happened, and what you expected;
- the smallest example that shows it.

Use made-up secrets. Never send a real password, key or token, and don't
attach your vault, your `gateway.toml`, transcripts or the audit log.

## In scope

- **Secret exposure.** A stored password, key or token reaches Claude (tool
  output, hook output, its context, the transcript), a log, a command line
  other processes can read, telemetry, or any program other than the one it
  was handed to.
- **Credential misuse.** A credential goes to a host or site it isn't bound
  to, or to a program that wasn't allowed it; or it is used after you
  narrowed the right (narrowing applies at once), or after you approved its
  removal in the dialog (until then the approved entry keeps gating).
- **Guard bypasses that reach a credential.** A way for Claude's commands to
  get or use a stored credential without the right and your OK: around the
  stand-ins, the approval hook, the consent dialog, the vault or the
  daemon's checks. Widening a right without the dialog counts too.

## Out of scope

- The limits the README states. For example, the gateway is a guardrail for
  a cooperative model, not a sandbox: code running as you can read what you
  can read.
- A bypass that reaches no credential, such as a harmless command running
  without a prompt. Open a normal issue for those.
- What Claude does with your own tools and credentials (your ssh agent and
  keys, your `GH_TOKEN`, your git and sudo) for targets you never put in
  `gateway.toml`: the gateway gates only what is configured.
- Bugs in Claude Code, pixi or the tools the gateway runs (OpenSSH, age,
  gh, tmux). Report those to their maintainers.

## What to expect

Reports are handled on a best-effort basis; there is no guaranteed response
time. You get an answer in the private report once it has been read. A fix
ships in a release with a CHANGELOG entry. Please allow time for that fix
before you disclose the problem publicly.
