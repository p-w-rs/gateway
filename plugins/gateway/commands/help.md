---
description: Quick guide to gateway - what it does and how to add accounts, secrets and sudo
---

Give the user a short, friendly guide to the gateway plugin, based on the
reference below. Write for someone who may never have used git, ssh or
tokens. Keep it to about a screen: a one-line summary, then the commands they
type, then what Claude can and can't do. Then call the `account_list` and
`secret_list` tools and show what the gateway holds now (names only; never
values). If their message has a question after the command, answer that
instead of the full guide.

Reference:

**What it is.** The gateway holds the user's passwords, tokens, SSH keys and
sign-ins, and is the only way Claude uses them. Claude never sees a value;
the gateway puts it into each request or command itself, sends it only where
the user allowed, and logs every use (`/gate:log`).

**Commands you type** (Claude takes it from there with a few questions;
anything secret is typed in a small dialog box, never in the chat):
- `/gate:add account`: GitHub, Hugging Face, a server over SSH, Azure /
  Databricks, the ASI ML Catalog, a container registry, Pijul. You can also
  say it directly: `/gate:add github`, `/gate:add ssh`, …
- `/gate:add secret`: an API key or token for a website.
- `/gate:add sudo`: a computer's administrator password, so Claude can run
  admin commands there. Each one still asks you first.
- `/gate:update NAME`: change something, e.g. `/gate:update github:work`.
- `/gate:delete NAME`: remove it.
- `/gate:enable sudo HOST` (or `… always`): let admin commands on that
  machine run without asking, for this session or always.
  `/gate:disable sudo HOST` undoes it.
- `/gate:enable exec ssh:NAME` (or `delete`, `write`, `read`; add `always`
  to keep it): stop asking before that kind of action on one account, e.g.
  running commands on your server. `/gate:disable exec ssh:NAME` asks again;
  `/gate:block write github:work` makes an account read-only.
- `/gate:enable reuse ssh:NAME`: keep that server's connection open for this
  session, so commands there are quicker.
- `/gate:export`: save everything to a file locked with a passphrase, to
  move it to another computer; `/gate:import FILE` brings it in there.
- `/gate:list`: what the gateway holds. `/gate:log`: what it did.

**On a machine with no screen** (over ssh): when a dialog can't open, Claude
gives you a command to run in a terminal there,
`pixi run --manifest-path …/pixi.toml gateway finish g-…`, which asks the same
thing at a hidden prompt.

**What Claude can and can't do.**
- Claude uses git, gh, hf, ssh, docker push/pull, Azure and the rest only
  through the gateway's tools, as the right account.
- In Claude's own terminal, those commands, your own tokens, your ssh-agent
  and your credential files are off limits.
- Deleting and running commands on servers ask you first (Claude Code's
  permission prompt), unless you switched that off with `/gate:enable`.
  A plain force-push is always refused.
- Admin (root) commands always ask, unless you enabled sudo for that machine.
- Claude can't add or change anything in the gateway by itself: every change
  starts with a command you type.
