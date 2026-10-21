# accounts group

Public API and behaviour of the modules the `accounts` group owns:
`scrub.py`, `githelper.py`, `clis.py`, `asiml.py`, `entra.py`, `logins.py`.
Contract: [SPEC-v3.md](../SPEC-v3.md) §9.4, §9.5, §9.6, §9.7, §11, §14.
Python 3.12 stdlib only. Every credential use writes an audit line
(`audit.use`); every refusal `audit.refusal`. Messages start with `gateway:`.

## scrub.py (SPEC 11)

- `secret_forms(value, user=None) -> [str]`: the forms one credential can take
  in output, each ≥ 8 chars — the value; its base64 (standard, url-safe, and
  the per-alignment base64 "cores" so the token is caught inside a longer
  `base64(user:value)` Basic-auth blob); `base64(user:value)`; URL-encoded
  (`quote`, `quote_plus`); JSON-escaped (`json.dumps(value)[1:-1]`, ASCII
  and non-ASCII spellings; round 4: a value with `"`, `\`, a control
  character or non-ASCII text, or a whole multi-line key, as a transcript or
  a JSON output holds it); each ≥ 16-char line of a multi-line value (an SSH
  key printed line by line) and its CRLF form. A value < 8 chars yields `[]`
  (masking it would reveal it).
- `expand(secrets, users=()) -> [bytes]`: every form of every secret, longest
  first.
- `Scrubber(secrets, users=(), expand_forms=True)`: a streaming byte filter.
  `feed(chunk) -> bytes` emits what is safe now, holding back only the longest
  suffix that is a proper prefix of some form; `flush() -> bytes` emits the
  rest at EOF. Masks every (overlapping) occurrence with `***`. Bytes-safe:
  binary without a secret passes through unchanged. `expand_forms=False` masks
  the given literals exactly (used by `scrub_text`). `release() -> bytes`
  emits what is held back now (`holding` says whether anything is); the
  released bytes stay in its window, so a secret that started there and is
  completed by later bytes is masked from where its unhandled part begins
  (its own `***` whenever clear bytes came out before it). Review round 2:
  holding back until EOF stalled interactive streams (a remote `printf c;
  read x` under sudo with the password "correct horse battery" never showed
  its prompt; `rsync --rsync-path='sudo rsync'` deadlocked on a protocol byte
  that starts the password's base64 form).
- `pump(src_fd, dst_fd, scrubber, close_src=True, idle=None) -> bool`: copy a
  fd through a scrubber, calling `release()` after `IDLE` (0.15 s) without
  new input; a closed reader (EPIPE) closes `src` so the writer gets SIGPIPE.
  ssh_conf.run_child's stderr and `-E` log pumps and the local sudo
  stand-in's stderr relay release the same way. Trade-off: a secret printed
  with a pause of more than `IDLE` in the middle shows the part before the
  pause (never the whole value).
- `run(argv, secrets, *, env=, cwd=, users=(), stdout_fd=1, stderr_fd=2,
  stdin=None, pass_fds=()) -> int`: run a child with stdout/stderr streamed
  through scrubbers (stdin inherited). Forwards SIGINT/SIGTERM/SIGHUP; returns
  the exit code (128+N for signal N). Raises OSError if it can't start.
- `scrub_text(text, extra=None) -> str`: masks every vault and cache value
  (≥ 8 chars, in all forms; cached per process by the vault/cache file stats)
  plus `extra` literals, then the shape patterns (`gh[pousr]_`, `github_pat_`,
  `hf_`, `glpat-`, `sk-`, `xox[abprs]-`, `AKIA…`, JWT, `AGE-SECRET-KEY-1…`,
  PEM private-key blocks, `Authorization: Bearer|Basic|token …`).
- `note_vault(data)` / `add_values(values)`: seed the per-process value cache
  from an already-decrypted vault, or add minted tokens (entra/ACR) to it.

## githelper.py (SPEC 9.4)

- `include_config(form, vault_meta) -> str`: the URL-scoped part of
  `$DATA/git/config` — one `[credential "SCHEME://HOST"]` section (helper reset
  + the gateway helper + `useHttpPath`) per git account host (github `host`,
  huggingface `huggingface.co`/`hf.co`); `[url "…/"] insteadOf` rewrites from
  the ssh forms to https for **token-only** hosts (every account on the host has
  a token and no ssh key, from `vault_meta`); and `[includeIf
  "hasconfig:remote.*.url:…"]` identity includes for each owner of an account
  that carries a commit `name`/`email`. **Never** emits the global
  `[credential] helper =` reset (envfile does). Loopback hosts use `http`.
- `identity_files(form) -> {name: content}`: `[user]` include files
  (`identity-<account>`), values quoted/escaped.
- `credential_main(argv) -> int`: `git-credential-gateway get|store|erase`.
  `get` answers only when the parent executable is `git-remote-http(s)` (or
  git's own `sh -c "<this data folder's helper> get"` between them, which
  dash, Debian's and Ubuntu's `/bin/sh`, keeps as a process where bash execs:
  the shell's argv must be exactly that and its parent git-remote-http(s);
  2026-10-20, found in the Linux VM; or git-lfs's `git credential fill`:
  parent `git`, grandparent `git-lfs`),
  protocol is https (http only for a loopback host under a test override),
  `GIT_TRACE_REDACT` is not `0/false`, `GIT_SSL_NO_VERIFY` is **absent** (git
  turns certificate checking off when the variable exists at all, even empty
  or `0`, verified with both gits) and `http.sslVerify` is not false **for the
  request URL** (`git config --type=bool --get-urlmatch http.sslVerify
  SCHEME://HOST/PATH`, so the URL-scoped `http.https://host/.sslVerify false`,
  repo/global/`-c`/env config all count; if git can't answer, e.g. a bad
  boolean, the helper refuses); it selects the account by host + path
  (`accounts.select`, honouring `GATE_ACCOUNT`), refuses an unbound host,
  returns `username` (`x-access-token` for GitHub, else the login) and the
  token. `store` is ignored; `erase` reads the whole request and marks stale
  only the account whose stored token equals the rejected `password`
  (`hmac.compare_digest`, github/huggingface accounts bound to the host); with
  no password, the account `get` would choose (`owner_from_path(path)`,
  `GATE_ACCOUNT`); an unknown password marks nothing (review round 4: it used
  `select(owner=None, env={})`, so a 401 on a work repo marked the default
  personal account). A stale token is refused with
  `accounts.stale_token_message(name)` (`... rejected; don't retry. Run gate
  check NAME while the user is here to enter a new one`: no pop-up opens by
  itself), the same line as gh, hf and `gate with`. Unknown host → no answer +
  a stderr line.

### Verified: `includeIf hasconfig` works from an env-provided include
`/opt/local/bin/git` 2.55 and `/usr/bin/git` 2.54 (Apple Git-157) both honour
`includeIf "hasconfig:remote.*.url:…"` when the including file is supplied
through `GIT_CONFIG_COUNT`/`include.path` (the env-file mechanism), choosing the
per-owner identity for https and ssh remotes under the owner and the global
identity otherwise. **No fallback is needed.**

## clis.py (SPEC 9.5, 9.6, 9.7)

- `main(tool, argv) -> int` for `gh|hf|databricks|crane|pijul|az`. Each:
  loads the form + vault, `consent.ratchet`s, picks the account for the owner
  (`accounts.select` with effective rights; SPEC 9.6 owner extraction per
  tool), checks the credential is bound to the destination, checks the caller
  is direct (`ancestry.is_direct`, else refuses unless the account has
  `scripts = true`), refuses the table's subcommands, builds the child env from
  an allowlist + forced endpoint variables + the credential in a temp config
  dir, runs the real binary from the pixi env by absolute path, streams output
  through the scrubber, audits.
  - gh → `GH_TOKEN`/`GH_ENTERPRISE_TOKEN`, `GH_HOST`, temp `GH_CONFIG_DIR`,
    prompts/browser off. Refuses `auth token|login|logout|refresh|setup-git|
    git-credential` wherever the word appears after `auth` (cobra finds the
    subcommand after flags: `gh auth -h HOST token`), `auth status` with
    `--show-token`, `--show-token=V`, `-t`, `-t=V` or `-t` in a short-flag
    cluster (`-at`), `extension`, `!`-aliases, `config set`. The token is in the
    scrubber's set regardless, so a missed spelling would still print `***`.
    Round 1: gh attaches `GH_ENTERPRISE_TOKEN` to every host but github.com
    and `GH_TOKEN` to any `*.ghe.com`, so a command line naming another host
    is refused (`gh_hosts`, `_gh_host_refused`): `--hostname`, `auth -h`,
    `-R/--repo HOST/OWNER/REPO` or a URL, URL arguments (`gh api
    https://h/...`, `gh pr view https://h/o/r/pull/1`, `git@h:o/r`) and
    `HOST/OWNER/REPO` arguments; only the account's host (or `api.<host>`)
    passes, and only when `consent.bound_ok` says the token is bound there.
  - hf → `HF_TOKEN`, forced `HF_ENDPOINT`, temp `HF_HOME`/token paths, real hub
    cache. Refuses `auth login|logout|token`, `--token`, `--endpoint`, `env`.
  - databricks → Entra token as `DATABRICKS_TOKEN`, `DATABRICKS_HOST` = the one
    listed workspace or the one named by `DATABRICKS_HOST`/`databricks.yml`
    (must be listed), `pat`, empty config file. Refuses `auth|configure`.
  - crane → per-call `DOCKER_CONFIG` with one auth chosen by image owner
    (ghcr → github account; `*.azurecr.io` → `entra.acr_token`, cached; else a
    registry account). Refuses `auth`.
  - pijul → `$DATA/pijul/bin/pijul`, temp HOME + known_hosts, `PIJUL_CONFIG_DIR`
    + identity.toml, `--config signing_key`, private agent. Refuses
    `identity|key|client`, `--config`. Not installed yet (conda-forge has no
    pijul): the first use starts one background build (`pixi run -e pijul
    install-pijul` with `CARGO_INSTALL_ROOT=$DATA/pijul`, lock dir
    `$DATA/pijul.building`, log `$DATA/pijul/build.log`) and exits 75 with
    "try again in a few minutes"; a binary whose build env (`.built-with`) is
    gone is rebuilt. Verified on osx-arm64: the binary links only the env's
    libraries (conda-forge libiconv, openssl, libsodium, zstd, zlib) by rpath.
    Tests use `testing.override(pijul_build=...)`; nothing is built otherwise.
  - az (minimal) → only `account get-access-token [--resource|--scope]
    [--tenant] [-o json]` and `account show`, and only when the azure account
    has an approved `env`. Round 1: `az_scope` mints only what the http tool
    would use for one of the account's approved, bound destinations
    (`web.azure_scope`, `may_send_to`, `consent.bound_ok`): Resource Manager
    (the default; `--resource https://management.core.windows.net/`, its
    legacy audience, gets the ARM scope), Graph, Storage when a storage
    account is listed (`https://storage.azure.com` or a listed account's own
    URL), Databricks when a workspace is listed, `https://SITE/.default` for a
    listed site; anything else (Key Vault, an `api://` app, another host, a
    widening not yet OK'd) is refused before anything is minted. The token
    JSON is printed as is (phase C decision), but only to a program that
    Claude's command started (an SDK's AzureCliCredential parses
    `accessToken`) and only with `scripts = true` (round 2): a direct caller
    (Claude's own command: shells and wrappers up to `CLAUDE_PID`, also under
    Monitor or in the background, whose streamed lines PostToolUse never
    sees) is refused with `AZ_DIRECT` (use the http tool), as is a caller
    whose ancestry can't be read; a program without `scripts = true` gets the
    "got no credential" line. Nothing is minted for a refused caller. The
    approval hook also denies `az … get-access-token` as Claude's own Bash or
    Monitor command (`az` is a prefilter word). Residual: with `scripts =
    true`, any program Claude writes can call az and print the token.
- `with_main(argv) -> int`: `gate with NAME -- CMD`. Only accounts with an
  approved `env`; var per kind (api-key→the key, huggingface→`HF_TOKEN`,
  github→`GH_TOKEN`); azure is refused (use `az`/http). Environment otherwise
  inherited; output scrubbed; direct check applies.
- Owner helpers: `gh_owner`, `hf_owner`, `crane_owner`, plus
  `accounts.owner_from_*`. `resolve_tool(name, feature=None)` resolves a binary
  from the pixi env (never PATH); optional feature envs are installed on first
  use with one stderr line (`install_feature`).

## asiml.py (SPEC 9.5)

- `main(argv, tool="asiml")`: `init datasets/NAME|models/NAME [--data-dir D]`,
  `clone NAME[@REV] [DIR]`, `pull [REV]`, `push`, `status`,
  `search [--kind K] QUERY`, `show NAME[@VER]`, `files NAME@VER [--prefix P]`.
  Reads the catalog over its API (Bearer = `entra.access_token` for the pinned
  `bound.scope`, else the host's `/api/config` API scope). Transfers get a
  short-lived storage pass and hand it to `dvc` (feature env) through an
  isolated config; the pass is scrubbed from all output.
- **Direct vs scripts (SPEC 9, 10)**: every command that uses the catalog
  token or a storage pass (`clone`, `pull`, `push`, `search`, `show`,
  `files`) checks `clis.is_direct(tool, scripts)` after the bound check; a
  non-direct caller without `scripts = true` on the ml-catalog account is
  refused (`gateway: asiml started by make got no credential …; run it as its
  own command, or set scripts = true for NAME`) before any catalog request.
  `init` and `status` use no credential and aren't gated.
- All catalog HTTP (`/api/config` and the API) goes through `entra.urlopen`:
  a 3xx is refused (`the catalog answered with a redirect, which the gateway
  doesn't follow with the sign-in token`), proxies and CA overrides ignored.
- `dvc_main(argv)`: inside an `.asiml` workspace, `dvc pull|push` → `asiml
  pull|push` (gated as `dvc`); everything else refused.

## entra.py (SPEC 9.5, 14)

- `access_token(account, scope) -> str`: cache.age first (valid ≥ 2 min), else
  mint under the vault lock from the refresh token, **persist the rotated
  refresh token**, cache the access token. Scopes: `arm|management`, `graph`,
  `storage`, `databricks` (`2ff814a6-3304-4ab8-85cb-cd0e6f879c1d/.default`), or
  a passed-through resource/scope. Never re-reads tenant/client from a changed
  host (uses the vault's pinned `entra` record).
- `scope_for_host(account, host, scope=None)`: the http tool's own rules
  (`web.azure_scope`): management→arm, graph→graph, a listed databricks
  workspace→databricks resource, a listed storage host→storage; a listed
  `site` needs an explicit `scope`, validated as `…/.default` and never a
  first-party audience (ARM, Graph, Storage, Databricks in any spelling);
  registries are refused (crane does the exchange). Raises EntraError.
- `acr_token(host, account)`: ARM-token → `/oauth2/exchange` → ACR refresh
  token, cached in cache.age (`acr:<host>`), for crane.
- Sign-ins: `login_browser` / `login_device` (PKCE and device code) were
  removed in PLAN-v4 phase 3 (no browser, web page or code to type
  elsewhere). An existing refresh token keeps working; a service principal
  (`client_secret` with the account's own `client_id` and `tenant`) mints
  tokens with the client-credentials grant (`access_token` uses it when
  there is no refresh token; `gate_setup.sp_token` checks a new one).
  Authority from `testing.override(entra_authority=...)` in tests;
  production always login.microsoftonline.com (never an env var).
- `urlopen(req, timeout=30)`, `opener()`, `tls_context()`, `is_redirect(e)`:
  the one HTTP client for every credentialed request in this group (Entra
  token endpoint, the ACR exchange, the catalog API, GitHub sign-in).
  **Never follows a redirect** (urllib would resend a caller-set
  `Authorization` header to the new host; a 3xx surfaces as `HTTPError` and
  each caller turns it into a `gateway:` refusal), **ignores proxy variables**
  (`ProxyHandler({})`), and verifies certificates against the Python build's
  own CA bundle (`ssl.get_default_verify_paths().openssl_cafile/capath`),
  **never `SSL_CERT_FILE`/`SSL_CERT_DIR`**: stand-ins run in Claude's
  environment, which must not choose a proxy or a trusted CA that would see a
  refresh or access token (SPEC 9 drops proxy/CA overrides). Tests may pass
  `testing.override(ssl_context=…)`.

## logins.py (SPEC 6, 15)

- `github_login(host, show, expected=None, timeout=) -> (token, login)`:
  GitHub OAuth **device flow** (gh's public client id), `show(code, url)`,
  poll, then `verify_login`. Raises `LoginError`.
- `verify_login(host, token, expected=None) -> login`: `GET /user`; raises on a
  bad token, an SSO block (clear "authorize the token for the org" hint), or a
  login that isn't `expected`. GitHub endpoints overridable in tests
  (`testing.override(github_base={"web":…, "api":…})`). Both go through
  `entra.urlopen` (no redirects, no proxies, the build's CA bundle).

## adapters.py: account adapters and states (PLAN-v4 phase 7)

One adapter per service names its credential methods (`METHODS`) and checks
a stored credential with one cheap API call, sent only to the account's
bound host (`consent.bound_ok`) through `entra.urlopen` (no redirects with
credentials, no proxies, the build's CA bundle):

| kind | methods | check |
|---|---|---|
| github | personal access token, fine-grained (`github_pat_`) or classic (`ghp_`) | `GET /user` on the account's API host; `github-authentication-token-expiration` tells an expired token (401 after that time) from a revoked one (401 before it); `x-github-sso` means the organisation wants SSO (reauthentication) |
| huggingface | user access token | `GET /api/whoami-v2` (401: revoked) |
| azure | service principal client secret; service principal certificate (PEM with the certificate and its unencrypted private key: a client assertion, RS256 signed by the env's openssl with the key on an inherited pipe, `entra.client_certificate`); a refresh token stored before phase 3 (the refresh grant; a rotated token is saved) | an ARM token; Entra's `error_codes` (`EntraError.codes`) sort into `ENTRA_EXPIRED`, `ENTRA_REVOKED`, `ENTRA_REAUTH` |

States (`STATES`): `missing`, `configured` (stored, not checked yet, or a
kind without a check), `connected`, `expired`, `revoked`,
`reauthentication_required`, `unknown` (no answer: network, rate limit,
5xx). They come only from the service's API answers to the gateway's own
stored credential: a browser login, `gh auth status` or a cookie never
counts as API authorization
(`test_accounts_states::test_a_browser_login_is_never_api_authorization`).
**No adapter needs a cookie or session store**: all three services take API
credentials; the only session-like state is an Entra refresh token, kept in
the vault's `entra` record as before (`test_no_adapter_needs_a_cookie_or_session_store`).

`check_and_record(name)` keeps the outcome in the vault
(`accounts[NAME].status`: state, checked_at, detail, safe facts: login, the
token's kind, its expiry; never a value); a new credential clears it
(`gate_setup._store_token`). gated's `Daemon.accounts()` reads them for
snapshots and `/gate-accounts`, and publishes a change as `account.state`.
`gate accounts [--check NAME|all] [--json]` lists or checks them. The
`/gate-accounts` pane shows each state with Check and Enter credential (`gate
login NAME`: the credential dialog; a PEM may be pasted with its line breaks,
because the dialog says `pem`: `clipboard.accept(multiline=True)` keeps line
breaks only for such a dialog, every other control character is still
refused).

Account policy (docs/modules/policy.md): `[accounts.NAME.policy]`
`credential`, `write`, `network`; `accounts.select` refuses an account whose
credential the policy doesn't allow (an "ask" only for a typed command), and
`web.http` refuses a non-GET request with an account whose `write` isn't
allow.

## Dependencies on other groups
- `ancestry.is_direct(tool, entry_scripts=False) -> (allowed, culprit)` (SPEC
  10) is the only walker (`clis.is_direct` calls it; any error there counts
  as not direct, so only `scripts = true` lets the credential through).
- `scrub.scrub_text` is what `audit.py` uses once this module landed.

## Review round 3 (2026-10-19)

- `accounts.select`: when usable accounts of the kind and host exist but
  none is chosen, the note names them and the ways to choose (`no account is
  chosen for H/O (A and B exist; neither lists O or is the default); set
  GATE_ACCOUNT=NAME, or ask the user to add default = true or owners`).
- hf gets its token in a 0600 file of the call's 0700 folder
  (`HF_TOKEN_PATH`), not in `HF_TOKEN` (`ps eww` shows a process's
  environment to the same user). gh, databricks, dvc and `gate with` still
  pass it in the environment (residual below).
- `gate with` and hf: a rejected token says to run `gate check NAME` while
  the user is here.

## Known residual limits (the "determined program" class, README "Security, honestly")
- The helper's parent check (like ancestry) compares the **basename** of the
  parent's executable path. A program that copies a binary to a file named
  `git-remote-https` (or `git-lfs`) and runs the helper from it passes. Only
  a deliberate attack does this; pinning the parent to the system git's
  exec-path would close it but would need a trust anchor Claude's PATH can't
  influence.
- The helper does not refuse custom CA settings (`GIT_SSL_CAINFO`,
  `http.sslCAInfo`) or `http.curloptResolve`; with a local interceptor these
  are equivalent to `sslVerify=false`. SPEC 9.4 doesn't list them, and
  refusing would break users whose own git config trusts a corporate CA.
- **Tokens in a running tool's environment** (round 3): gh (`GH_TOKEN` /
  `GH_ENTERPRISE_TOKEN`), databricks (`DATABRICKS_TOKEN`), dvc under asiml
  (`AZURE_STORAGE_SAS_TOKEN`) and `gate with` (its variable) hold the
  credential in their environment while they run; on macOS (Darwin 25) and
  Linux `ps eww -p PID` prints a same-user process's environment (macOS hides
  it only for platform binaries, not the pixi tools). Claude's `ps auxeww`
  during a long `gh repo clone` shows the token; PostToolUse masks it (the
  value is in the vault) when the command succeeds; a failed command's
  output, Monitor's lines and a background command's notice reach Claude as
  they are (known limits since the rollback, DECISIONS "Rolled back"; the
  optional `gate scrub` masks what is piped through it). hf uses a 0600 file
  instead; a file is still same-user readable, just not shown by an innocent
  `ps`.
