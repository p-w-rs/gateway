# Kickoff prompt — paste this to start the review agent

> Copy everything in the block below into a fresh Claude Code session opened in
> `~/projects/hobby/net-gateway` (ideally a high-capability model).

---

You are reviewing and then installing a Claude Code plugin I built. The project
root is `~/projects/hobby/net-gateway`. Start by reading `HANDOFF.md` in that
directory in full — it describes the goal, architecture, approval design, install
steps, and the specific risks to scrutinize. Then read the actual source under
`plugins/net-gateway/` (don't trust the handoff; verify against the code).

Do this in order:

1. **Critical review.** Assess correctness, security, and portability. Pay
   particular attention to:
   - The claim that everything is Python standard library only (grep for
     non-stdlib imports).
   - `write_request` being `auto` with `allow_domains: ["*"]` — is this an
     acceptable exfiltration surface, or should it be tightened? Recommend.
   - The PreToolUse regex hook as a guardrail vs. a real boundary — can it be
     trivially bypassed, and does that matter for the stated goal?
   - Secret handling: confirm no secret value is ever returned to the model or
     written to the audit log.
   - The redaction patterns and the `secret_list` keychain parsing.
   Report findings grouped by severity. Do NOT change behavior I chose
   deliberately (see HANDOFF §5) without flagging it and asking me first.

2. **Run the checks.**
   `cd plugins/net-gateway && pixi install && pixi run test && claude plugin validate .`
   and `claude plugin validate .` at the root. All tests must pass.

3. **Install** per HANDOFF §8: add the local marketplace, install
   `net-gateway@local-tools`, reload, then **confirm the real MCP tool permission
   names** (HANDOFF §7) and fix `settings.proposed.json` if they differ. Verify
   the MCP server loads and `/net-log` works, and that a `curl ...` command is
   correctly redirected.

4. **Replace my settings** per HANDOFF §9 — but **back up both settings files
   first**, show me a diff of what you're removing (the ~90 one-off `Bash(...)`
   allows) vs. keeping (my 4 preference keys + the new allow/ask/deny rules), and
   get my explicit confirmation before overwriting. Clear the stale allowlist in
   `~/.claude/settings.local.json` only after I confirm.

Stop and ask me before step 3 and before step 4. Summarize your review findings
before installing anything.
