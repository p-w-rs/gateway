---
name: accounts
description: Use the user's separate gateway accounts (several GitHub, Hugging Face, Pijul, Azure, ASI ML Catalog, SSH, registry identities) for git, gh, mirrors and APIs, and set up or change repos mirrored between accounts (e.g. personal and work) when the user asks in plain words. Read before any git push/pull/clone, gh, hf, pijul or mirror work, or when the user mentions an account, a profile, "my work GitHub", "keep these in sync", or SSO.
---

# Working with gateway accounts

The user keeps separate identities in the gateway vault as accounts named
`KIND:NAME`, e.g. `github:personal` and `github:work`. You never see their
tokens or keys. The tools pick the right one and inject it per call. The
session-start note and `account_list` show each account's login, the owners
and hosts it's for, its methods (token, ssh_key) and its prompt policy.

## Rules

- **All git goes through the `git` tool**, never git in Bash, even
  `status`. Pass `args` (without "git") and an absolute `cwd`.
  - Local commands run without credentials.
  - For fetch/pull/push/clone/ls-remote, the gateway picks the account from
    the remote's host and owner.
  - Pass `account=` only when several fit, or the user names one.
- **GitHub CLI work goes through the `gh` tool**, never gh in Bash. Clones
  and checkouts use the `git` tool.
- **Commit as the right person:** in a repo that belongs to one account,
  call `git_identity` once (cwd, account) before committing. In a mirrored
  repo, commit as the account the user says (ask if it's unclear) and keep
  that identity.
- **When a tool answers `use: git_confirm`** (or `gh_confirm`), the
  account's policy wants the user to approve: call the `_confirm` tool with
  the same arguments, and Claude Code asks them. Don't look for ways around
  it.
- **Never use the user's own environment** for a service that has an
  account here: no `GITHUB_TOKEN`, ssh agent, `~/.ssh` keys or credential
  helpers.
- **Missing or not allowed?** Tell the user the exact command. You can't run
  these yourself:
  - `/gate:account add github NAME <description>` (a browser form asks the
    login, owners, token or SSH key);
  - `/gate:account login github:NAME` (SSO / web sign-in, needed for
    SSO-only orgs like asirobots);
  - `/gate:account allow github:NAME OWNER`;
  - `/gate:account prompts github:NAME write=ask|auto delete=ask|refuse`.
- **Plain force pushes are refused.** If the user really wants to overwrite
  a remote, use `--force-with-lease` through `git_confirm`.

## Mirrors: one repo, several remotes and accounts

When the user says something like "keep this repo in sync between my
personal and work GitHub":

1. **Remotes.** Make sure each side is a remote, adding them with the
   `git` tool if needed: `remote add personal https://github.com/<me>/<repo>.git`,
   `remote add work https://github.com/<org>/<repo>.git`. Each remote's
   host and owner decide its account. Check with `account_list` that both
   are covered.
2. **Save the set.** `git_mirror` with `action=add`, `remotes=[...]`. It's
   stored in the repo's `gateway.mirror` config, so it survives sessions.
3. **Look first.** `git_mirror` with `action=status` shows per branch
   whether the remotes are in sync, behind (and which), or diverged, and
   the same for tags.
4. **Sync.** `git_mirror` with `action=sync` fast-forwards the remotes that
   are behind, each pushed as its own account.
   - Diverged branches and conflicting tags are left alone. Explain which
     commits differ and ask the user which side wins, or merge or rebase
     locally with the `git` tool and sync again.
   - Pushes the policy wants confirmed come back under `needs_confirm`: run
     each with `git_confirm`.
5. **Afterwards.** When the user commits and pushes to one side, offer to
   sync the mirror. Use `branches=[...]` to keep only some branches in sync
   if the user wants (e.g. not `wip/*` on the work side). Tell them what you
   kept apart.

`action=remove` drops remotes from the saved set; it never touches the
remotes themselves.

## Several accounts in one task

It's normal to use two accounts in one task, e.g. open a PR on the work repo
(`gh` with `account=github:work`) and mirror the same branch to personal
(`git_mirror`). Say which account each step used. If the user's words
("my work GitHub", "the asirobots one") map to an account, use it; if not,
ask.

## Servers over SSH

`ssh_exec` runs a command (argv list) and `ssh_copy` copies files as an
`ssh:NAME` account; root goes through `run_privileged`. The gateway writes
its own ssh config for each call, so the user's `~/.ssh/config` aliases
don't apply: use the account name. An account can have several routes (for
example home LAN, then a forwarded port); the gateway picks one and the
result says which (`route`, `route_why`). `ssh_hosts` shows the routes,
host-key policy and fingerprints, and, with `probe=true`, which route it
would use now. If a host key changed, say so plainly and don't work around
it; the user decides with `/gate:update ssh:NAME`. For many quick calls in
a row, the user can type `/gate:enable reuse ssh:NAME` to keep the
connection open for this session. Suggest it; never assume it's on.
