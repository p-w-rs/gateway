#!/bin/sh
# The gateway's launcher (SPEC 18). POSIX sh; runs before Python exists.
#
#   launch.sh hook-session        SessionStart (sync); degraded output while the env builds
#   launch.sh hook-subagent|hook-bash|hook-files|hook-post|hook-prompt|hook-filechanged|hook-mcp
#   launch.sh mcp                 the MCP server (waits up to 4 s for the env, else exits 1)
#   launch.sh ensure-env          build the pixi env (async SessionStart hook, or the mod's
#                                 session.start), then write the managed shell's files
#                                 (run.py managed-sync), clean old ones
#   launch.sh status              one JSON line for the mod and /gate-doctor: env, readiness,
#                                 build state, pixi, vault presence (never reads the vault)
#   launch.sh e2e-root            the e2e copy's validated root and run dir (hooks/e2e.sh)
#   launch.sh MODE ARGS...        run.py MODE ARGS... (or "still setting up", exit 75)
#
# The env lives in $DATA/envs/<sha12 of pixi.lock>/ (copied pixi.toml + pixi.lock,
# `pixi install --locked`, immutable once built, marked by .ready). Python runs
# with -X pycache_prefix=$DATA/pycache: its bytecode cache stays out of the
# plugin folder (versioned content, maybe read-only), without paying a
# recompile on every hook call as -B would.
set -u

case $0 in */*) _here=${0%/*} ;; *) _here=. ;; esac   # dirname, without a process
ROOT=$(CDPATH='' cd -- "$_here/.." && pwd -P) || exit 1
mode=${1-}
# The user's home from the password database, as paths.user_home() (never
# $HOME, which Claude Code may have pointed elsewhere; hooks/home.sh). Tests
# only: `launch.sh MODE --test` with an absolute GATEWAY_TEST_ROOT puts it in
# the test root (as run.py --test does); GATEWAY_TEST_ROOT without a valid
# --test resolves no home at all (run.py exits 2 then), so a test can never
# reach the real ~/.config/gateway through the degraded paths.
UHOME=${HOME:-/nonexistent}
if [ -n "${GATEWAY_TEST_ROOT-}" ]; then
  UHOME=/nonexistent
  if [ "${2-}" = --test ]; then
    case $GATEWAY_TEST_ROOT in /*) UHOME="$GATEWAY_TEST_ROOT/home" ;; esac
  fi
elif [ -f "$ROOT/hooks/home.sh" ]; then
  . "$ROOT/hooks/home.sh"
  UHOME=$(gw_user_home)
fi
# The e2e suite's scratch copy (hooks/e2e.sh, tests/e2e/README.md): its data
# folder lives in the e2e root. Production has no marker.
GW_E2E_ROOT=
GW_E2E_RUN=
if [ -f "$ROOT/e2e-root" ] && [ -f "$ROOT/hooks/e2e.sh" ]; then
  . "$ROOT/hooks/e2e.sh"
  gw_e2e "$ROOT"
fi
if [ -n "$GW_E2E_ROOT" ]; then
  DATA="$GW_E2E_ROOT/data"
elif [ -n "${CLAUDE_PLUGIN_DATA-}" ]; then
  DATA=$CLAUDE_PLUGIN_DATA
else
  DATA="${CLAUDE_CONFIG_DIR:-$UHOME/.claude}/plugins/data/gate-gateway"
fi
# Python's bytecode cache (paths.pycache_dir()): never __pycache__ beside the
# plugin's sources (a test runs a copy and checks).
PYC="$DATA/pycache"
if [ "$mode" = e2e-root ]; then   # for the e2e suite's pre-flight check
  [ -n "$GW_E2E_ROOT" ] || exit 1
  printf '%s\n%s\n' "$GW_E2E_ROOT" "$GW_E2E_RUN"
  exit 0
fi

# The file guard's fast path (review round 5; SPEC 12). Python (hooks_files)
# costs every Read, Edit, Write, MultiEdit and NotebookEdit 30-60 ms, nearly
# all of it starting the interpreter. A call that plainly can't touch a
# protected location gets no decision here, without Python; anything this
# can't settle goes to Python, which decides in full. It passes a call only
# when ALL of these hold (each check errs towards Python):
#  - the payload names "tool_name", "cwd" and the path key ("file_path", or
#    "notebook_path" for NotebookEdit) exactly once each (JSON escapes a
#    quote inside a string, so those are the real keys), and neither the
#    other path key nor "path"; the tool is one of the five;
#  - the path and cwd are absolute, made only of ASCII letters, digits,
#    space and . _ / + @ , = - (no backslash, so no JSON escape; no ~, no
#    glob, nothing that could fold to another name), with no empty, "." or
#    ".." part; the path lies inside cwd;
#  - the path (any letter case) doesn't end in .jsonl (session transcripts),
#    contains no /.config/gateway (the e2e copy's real home, compared as
#    text only) and isn't under /tmp/gw-* or /private/tmp/gw-* (run dirs);
#  - no part of the path, from the top down to the file, is a symlink, a
#    file with more path below it (Python checks the inode of every part:
#    a hard link to a protected file), or the
#    same file (`test -ef`: device and inode, so any spelling) as the
#    gateway home, its private/, key.txt or store.age (followed if they are
#    symlinks) or the test/e2e run dir; private/ holds no symlink (Python
#    protects their targets too);
#  - an existing target is a regular file with one link (a hard link to a
#    protected file has two).
# (The tool list, the "." / ".." rule and "inside cwd" are defence in depth:
# the key checks and the inode walk catch what they would. tests/
# test_ux_hooks.py compares this with Python case by case, and each other
# check has a mutation in tests/mutations_ux.py.)
GW_PAYLOAD=
gw_fast_files() {
  case $UHOME in /nonexistent|'') return 1 ;; esac
  [ / -ef / ] 2>/dev/null || return 1                # a test(1) without -ef: Python
  case $GW_PAYLOAD in *\"path\"*) return 1 ;; esac
  _t=${GW_PAYLOAD#*\"tool_name\"}
  case $_t in
    :\"Read\"*|:\"Edit\"*|:\"Write\"*|:\"MultiEdit\"*|': "Read"'*|': "Edit"'*|': "Write"'*|': "MultiEdit"'*)
      _k=file_path; _o=notebook_path ;;
    :\"NotebookEdit\"*|': "NotebookEdit"'*) _k=notebook_path; _o=file_path ;;
    *) return 1 ;;
  esac
  case $_t in *\"tool_name\"*) return 1 ;; esac
  case $GW_PAYLOAD in *\""$_o"\"*) return 1 ;; esac
  gw_json_str "$_k" || return 1
  _f=$GW_STR
  gw_json_str cwd || return 1
  _c=$GW_STR
  for _x in "$_f" "$_c"; do
    case $_x in
      /*) ;;
      *) return 1 ;;
    esac
    case $_x in
      *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/+@,=' '-]*) return 1 ;;
      *//*|*/./*|*/../*|*/.|*/..|*/) return 1 ;;
    esac
  done
  case $_f in "$_c"/?*) ;; *) return 1 ;; esac
  case $_f in
    *.[Jj][Ss][Oo][Nn][Ll]) return 1 ;;
    */.[Cc][Oo][Nn][Ff][Ii][Gg]/[Gg][Aa][Tt][Ee][Ww][Aa][Yy]|*/.[Cc][Oo][Nn][Ff][Ii][Gg]/[Gg][Aa][Tt][Ee][Ww][Aa][Yy]/*) return 1 ;;
    /[Tt][Mm][Pp]/[Gg][Ww]-*|/[Pp][Rr][Ii][Vv][Aa][Tt][Ee]/[Tt][Mm][Pp]/[Gg][Ww]-*) return 1 ;;
  esac
  if [ -n "$GW_E2E_ROOT" ]; then
    _h="$GW_E2E_ROOT/home/.config/gateway"; _r=${GW_E2E_RUN:-$GW_E2E_ROOT/run}
  elif [ -n "${GATEWAY_TEST_ROOT-}" ]; then
    _h="$UHOME/.config/gateway"; _r="$GATEWAY_TEST_ROOT/run"
  else
    _h="$UHOME/.config/gateway"; _r=/tmp/gw-
  fi
  if [ -d "$_h/private" ]; then
    [ -z "$(find "$_h/private" -type l -print 2>/dev/null)" ] || return 1
  fi
  _rest=${_f#/}
  _pre=
  while [ -n "$_rest" ]; do
    _pre="$_pre/${_rest%%/*}"
    case $_rest in */*) _rest=${_rest#*/} ;; *) _rest= ;; esac
    [ -L "$_pre" ] && return 1
    [ -e "$_pre" ] || break                          # nothing below it exists yet
    [ -z "$_rest" ] || [ -d "$_pre" ] || return 1    # a file with a path below it
    for _q in "$_h" "$_h/private" "$_h/key.txt" "$_h/store.age" "$_r"; do
      [ "$_pre" -ef "$_q" ] && return 1
    done
  done
  if [ -e "$_f" ]; then
    [ -f "$_f" ] || return 1
    [ -n "$(find "$_f" -prune -links 1 -print 2>/dev/null)" ] || return 1
  fi
  return 0
}

# Sets GW_STR to the raw text of the JSON string value of key $1 in
# GW_PAYLOAD, up to the first quote, when the key appears exactly once. A
# value with an escape keeps its backslash (an escaped quote ends the text
# there), which the caller's character check refuses.
gw_json_str() {
  GW_STR=
  _a=${GW_PAYLOAD#*\""$1"\"}
  [ "$_a" != "$GW_PAYLOAD" ] || return 1
  case $_a in *\""$1"\"*) return 1 ;; esac
  _a=${_a#"${_a%%[! ]*}"}
  case $_a in :*) _a=${_a#:} ;; *) return 1 ;; esac
  _a=${_a#"${_a%%[! ]*}"}
  case $_a in \"*) _a=${_a#\"} ;; *) return 1 ;; esac
  GW_STR=${_a%%\"*}
  [ "$GW_STR" != "$_a" ] || return 1
  return 0
}

if [ "$mode" = hook-files ]; then
  GW_PAYLOAD=$(cat)
  if gw_fast_files; then
    exit 0
  fi
fi

STILL="gateway: still setting up (first run); try again in a minute"
NOPIXI="gateway: the gateway can't set itself up: pixi isn't installed; tell the user to install it from https://pixi.sh and start a new session"
# The launcher is the user's own helper: its texts speak to the user
# (envfile.launcher_not_ready).
LSTILL=$STILL
LNOPIXI="gateway: pixi isn't installed, so the gateway can't set itself up; install it from https://pixi.sh and start a new Claude Code session"
# How pixi is updated (envfile.PIXI_UPDATE, lib.ts's PIXI_UPDATE): pixi
# self-update refuses a Homebrew or MacPorts pixi.
GW_PIXI_UPDATE="pixi self-update, or your package manager for a Homebrew or MacPorts pixi"

# Sets SHA: the first 12 hex digits of sha256(FILE), as paths.lock_sha12()
# (nolock000000 when it can't be had). No subshell or cut: every hook call
# runs this (review round 5).
sha12() {
  SHA=nolock000000
  [ -f "$1" ] || return 0
  if command -v sha256sum >/dev/null 2>&1; then s=$(sha256sum "$1")
  elif command -v openssl >/dev/null 2>&1; then s=$(openssl dgst -sha256 -r "$1")
  elif command -v shasum >/dev/null 2>&1; then s=$(shasum -a 256 "$1")
  else return 0; fi
  s=${s%%[!0-9a-f]*}
  [ "${#s}" -ge 12 ] || return 0
  while [ "${#s}" -gt 12 ]; do s=${s%?}; done
  SHA=$s
}

sha12 "$ROOT/pixi.lock"
ENVD="$DATA/envs/$SHA"
PY="$ENVD/.pixi/envs/default/bin/python3"

ready() { [ -x "$PY" ] && [ -e "$ENVD/.ready" ]; }

# The lock's Python minor ("3.15"): the python package of pixi.lock's default
# environment, one minor on every platform; "" when it can't be told (no
# lock, no python, or two minors). envfile.lock_python_minor reads the same.
lock_py_minor() {
  awk '
    /^environments:/ { e = 1; next }
    e && /^[^ ]/ { exit }
    e && /^  [^ ]/ { d = ($0 == "  default:"); next }
    d && /^      - conda: .*\/python-[0-9]+\.[0-9]+\.[^\/]*$/ {
      s = $0; sub(/.*\/python-/, "", s); split(s, v, "."); m = v[1] "." v[2]
      if (f == "") f = m; else if (f != m) bad = 1
    }
    END { if (!bad) print f }' "$ROOT/pixi.lock" 2>/dev/null
}

# The newest other env that finished building, or "": while an update's env
# builds (a new pixi.lock), hooks, the MCP server and (through the stubs
# Python writes) the stand-ins keep running on it; the code is stdlib-only,
# so an older env's Python runs it, but only one on the lock's Python minor
# (its bin/python3.MINOR): new code never runs on the previous Python (a 3.12
# env with code for 3.15; PLAN-0.11 section 5). Without one the cold paths
# apply until the new env is ready.
older_env() {
  best=""
  _m=
  _mk=
  for d in "$DATA/envs"/*; do
    [ -d "$d" ] || continue
    case ${d##*/} in "$SHA"|*.*) continue ;; esac
    [ -x "$d/.pixi/envs/default/bin/python3" ] && [ -e "$d/.ready" ] || continue
    if [ -z "$_mk" ]; then _m=$(lock_py_minor); _mk=1; fi
    [ -n "$_m" ] && [ -x "$d/.pixi/envs/default/bin/python$_m" ] || continue
    if [ -z "$best" ] || [ -n "$(find "$d/.ready" -newer "$best/.ready" 2>/dev/null)" ]; then
      best=$d
    fi
  done
  printf '%s' "$best"
}

find_pixi() {
  p=$(command -v pixi 2>/dev/null) && [ -x "$p" ] && { printf '%s\n' "$p"; return 0; }
  for d in "${PIXI_HOME:-${HOME:-}/.pixi}/bin" "${HOME:-}/.local/bin" /opt/homebrew/bin \
           /usr/local/bin /opt/local/bin /home/linuxbrew/.linuxbrew/bin; do
    [ -x "$d/pixi" ] && { printf '%s\n' "$d/pixi"; return 0; }
  done
  return 1
}

# POSIX single-quoting (same as envfile.sq)
# (sed only for a value with a quote: SessionStart quotes a few paths each time)
q() {
  case $1 in
    *\'*) printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")" ;;
    *) printf "'%s'" "$1" ;;
  esac
}

# The env file: byte-identical to envfile.env_text(). Everything after
# GW_BIN= runs only while the stand-in folder exists (env.sh is sourced by
# other launchers too, such as checkpoint jobs, also after an uninstall); in
# Claude Code's own shell (CLAUDECODE) it also unsets Claude Code's own
# credential variables and the present stand-ins' aliases and functions.
# shellcheck disable=SC2016  # the $ signs are meant literally
env_text() {
  B="$DATA/bin"
  printf '%s\n' "# gateway: Claude's environment (regenerated at every session start)."
  printf '%s\n' '# Safe to source elsewhere (a checkpoint job, a terminal): it does nothing once'
  printf '%s\n' "# the gateway's stand-in folder is gone."
  printf 'GW_BIN=%s\n' "$(q "$B")"
  printf '%s\n' 'if [ -d "$GW_BIN" ]; then'
  printf '%s\n' '  case ":${PATH-}:" in *":$GW_BIN:"*) ;; *) PATH="$GW_BIN${PATH:+:$PATH}"; export PATH;; esac'
  printf '%s\n' '  if [ -n "${CLAUDECODE-}" ]; then'
  printf '%s\n' '    unset CLAUDE_CODE_OAUTH_TOKEN CLAUDE_CODE_MESSAGING_TOKEN CLAUDE_CODE_CLIENT_KEY CLAUDE_CODE_CLIENT_KEY_PASSPHRASE CLAUDE_CODE_CLIENT_CERT CLAUDE_CODE_HOST_CREDS_FILE ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN'
  printf '%s\n' "    for _gw_n in $STUB_STANDINS; do"
  printf '%s\n' '      if [ -f "$GW_BIN/$_gw_n" ]; then unalias "$_gw_n" 2>/dev/null || :; unset -f "$_gw_n" 2>/dev/null || :; fi'
  printf '%s\n' '    done'
  printf '%s\n' '    unset _gw_n'
  printf '%s\n' '  fi'
  printf '%s\n' 'fi'
}

# One stand-in stub: byte-identical to envfile.stub_text(NAME, ARGS).
# shellcheck disable=SC2016
# The quoted paths come from write_stubs (quoted once there: each $(q) is a
# subshell); the args are write_stubs' own words, which hold no quote.
stub() {
  name=$1; shift
  args=""
  for a in "$@"; do args="$args '$a'"; done
  printf '%s\n' '#!/bin/sh'
  printf '%s\n' '# gateway stand-in (regenerated at every session start)'
  printf 'GW_DATA=%s; export GW_DATA; unset CLAUDE_PLUGIN_DATA\n' "$_QDATA"
  printf 'if [ -x %s ] && [ -e %s ]; then exec %s -I -S -X %s %s%s "$@"; fi\n' \
    "$_QPY" "$_QREADY" "$_QPY" "$_QPYC" "$_QRUN" "$args"
  if [ "$name" = sudo ]; then
    printf '%s\n' 'exec /usr/bin/sudo "$@"'
  else
    if [ "$name" = git ]; then git_cold; fi
    printf 'echo %s >&2\nexit 75\n' "$_QSTILL"
  fi
}

# The git stub's way while no env can run Python (byte-identical to
# envfile.git_cold_lines(); PLAN-0.11 §6.6): with nothing that may be
# configured (maybe_configured's rule, at run time), the user's own git,
# found as envfile.user_tool finds it; else still setting up.
# shellcheck disable=SC2016
git_cold() {
  printf 'if [ ! -f %s ] && ! grep -Eq %s %s 2>/dev/null; then\n' "$_QCONF" "$_QERE" "$_QFORM"
  printf '%s\n' '  _gw_ifs=$IFS; IFS=:; set -f'
  printf '%s\n' '  for _gw_d in ${PATH-}:/usr/local/bin:/opt/homebrew/bin:/opt/local/bin:/usr/bin:/bin; do'
  printf '%s\n' '    case $_gw_d in /*) ;; *) continue ;; esac'
  printf '    case $_gw_d/ in %s/*|%s/*) continue ;; esac\n' "$_QENVS" "$_QPIXI"
  printf '%s\n' '    [ -f "$_gw_d/.gateway-standins" ] && continue'
  printf '%s\n' '    [ -f "$_gw_d/git" ] && [ -x "$_gw_d/git" ] || continue'
  printf '%s\n' '    if [ "$_gw_d/git" = /usr/bin/git ] && [ -x /usr/bin/xcode-select ] && ! /usr/bin/xcode-select -p >/dev/null 2>&1; then continue; fi'
  printf '%s\n' '    IFS=$_gw_ifs; set +f; exec "$_gw_d/git" "$@"'
  printf '%s\n' '  done'
  printf '%s\n' '  IFS=$_gw_ifs; set +f'
  printf '%s\n' 'fi'
}

GONE="gateway: this launcher points at a gateway plugin that isn't there any more (uninstalled, or updated since the last Claude Code session); start a Claude Code session with the plugin to renew it, or delete ~/.config/gateway/gate if you uninstalled the gateway"

# ~/.config/gateway/gate: byte-identical to envfile.launcher_text() (while the
# env builds; messages name it from the first session on).
# shellcheck disable=SC2016
launcher_text() {
  printf '%s\n' '#!/bin/sh'
  printf '%s\n' "# The gateway's helper for your own terminal (regenerated at every Claude Code"
  printf '%s\n' '# session start). Try: ~/.config/gateway/gate status   or   gate log'
  printf 'GW_DATA=%s; export GW_DATA; unset CLAUDE_PLUGIN_DATA\n' "$(q "$DATA")"
  printf 'if [ -x %s ] && [ -e %s ]; then exec %s -I -S -X %s %s %s "$@"; fi\n' \
    "$(q "$PY")" "$(q "$ENVD/.ready")" "$(q "$PY")" "$(q "pycache_prefix=$PYC")" "$(q "$ROOT/run.py")" "$(q gate)"
  printf 'if [ ! -f %s ]; then echo %s >&2; exit 1; fi\n' "$(q "$ROOT/run.py")" "$(q "$GONE")"
  printf 'echo %s >&2\nexit 75\n' "$(q "$LSTILL")"
}

write_launcher() {
  if [ -n "$GW_E2E_ROOT" ]; then
    H="$GW_E2E_ROOT/home/.config/gateway"
  else
    case $UHOME in /?*) H="$UHOME/.config/gateway" ;; *) return 0 ;; esac
  fi
  if [ -L "$H" ] || { [ -e "$H" ] && [ ! -d "$H" ]; }; then return 1; fi
  (umask 077 && mkdir -p "$H") || return 1
  t="$H/.gate.$$.tmp"
  if launcher_text > "$t" && chmod 700 "$t" && mv -f "$t" "$H/gate"; then :; else rm -f "$t"; fi
}

# Each stub is replaced atomically inside the existing folder (temp file, then
# mv -f = rename), so $DATA/bin never goes missing (same as envfile.write_stubs).
# `write_stubs all` writes the full base set (envfile.BASE_STANDINS: the cold
# window, while something may be configured; Python narrows it to what the
# configured set needs), `write_stubs helpers` only gate and the helpers (and
# removes the stand-ins: nothing is configured). Either way the folder gets
# its marker (envfile.STANDIN_MARKER), which the pass-through's PATH lookup
# skips.
write_stubs() {
  B="$DATA/bin"
  if [ -L "$B" ] || { [ -e "$B" ] && [ ! -d "$B" ]; }; then rm -f "$B"; fi
  mkdir -p "$B" || return 1
  chmod 755 "$B"
  _QDATA=$(q "$DATA"); _QPY=$(q "$PY"); _QREADY=$(q "$ENVD/.ready"); _QRUN=$(q "$ROOT/run.py")
  _QPYC=$(q "pycache_prefix=$PYC")
  _QSTILL=$(q "$STILL")
  _h=$(gw_home)
  _QCONF=$(q "$_h/private/configured.json"); _QFORM=$(q "$_h/gateway.toml")
  _QERE=$(q "$CONFIGURED_ERE"); _QENVS=$(q "$DATA/envs"); _QPIXI=$(q "$ROOT/.pixi")
  names=" "
  made=""
  _specs=
  if [ "${1-all}" = all ]; then
    for n in $STUB_STANDINS; do _specs="$_specs $n:shim:$n"; done
  fi
  for spec in $_specs gate:gate git-credential-gateway:git-credential gate-askpass:askpass; do
    _ifs=$IFS; IFS=:
    # shellcheck disable=SC2086
    set -- $spec
    IFS=$_ifs
    n=$1; shift
    if stub "$n" "$@" > "$B/.$n.tmp.$$"; then made="$made $n"; else rm -f "$B/.$n.tmp.$$"; fi
    names="$names$n "
  done
  if [ "$(cat "$B/.gateway-standins" 2>/dev/null)" != "$MARKER_TEXT" ]; then
    printf '%s\n' "$MARKER_TEXT" > "$B/.gateway-standins.tmp.$$" && chmod 644 "$B/.gateway-standins.tmp.$$" &&
      mv -f "$B/.gateway-standins.tmp.$$" "$B/.gateway-standins" || rm -f "$B/.gateway-standins.tmp.$$"
  fi
  chmod 755 "$B"/.*.tmp.$$ 2>/dev/null        # one chmod for all of them
  for n in $made; do
    t="$B/.$n.tmp.$$"
    if [ -x "$t" ] && mv -f "$t" "$B/$n"; then :; else rm -f "$t"; fi
  done
  for f in "$B"/*; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    case $names in *" ${f##*/} "*) ;; *) rm -f "$f" ;; esac
  done
  find "$B" -name '.*.tmp.*' -mmin +60 -exec rm -f {} + 2>/dev/null
  for f in "$DATA"/bin.new.* "$DATA"/bin.old.*; do   # the old layout
    [ -e "$f" ] && rm -rf "$f"
  done
  return 0
}

# $CLAUDE_ENV_FILE, replaced whole (a temp file renamed over it, as
# envfile.write_env_file): a hook killed meanwhile leaves the old file or the
# new one, never a cut-short one. Claude Code sources only names like
# sessionstart-hook-N.sh, never the temp file.
write_env_file() {
  [ -n "${CLAUDE_ENV_FILE-}" ] || return 0
  case $CLAUDE_ENV_FILE in */*) mkdir -p "${CLAUDE_ENV_FILE%/*}" 2>/dev/null ;; esac
  t="$CLAUDE_ENV_FILE.gw$$.tmp"
  if env_text > "$t" 2>/dev/null && mv -f "$t" "$CLAUDE_ENV_FILE" 2>/dev/null; then :; else rm -f "$t"; fi
}

# The stand-ins of the base set and the helpers (envfile.STANDIN_NAMES,
# envfile.HELPERS; write_stubs above), and the stand-in folder's marker text
# (envfile.MARKER_TEXT, without its newline).
STUB_STANDINS="sudo ssh scp sftp git gh hf databricks crane pijul asiml az dvc"
STUB_HELPERS="gate git-credential-gateway gate-askpass"
MARKER_TEXT="gateway stand-ins: user_tool skips this folder"

# May something be configured (PLAN-0.11 §1.2's cold rule, before any Python
# can tell)? gateway.toml has a line that starts the hosts or accounts table
# in any shape TOML allows: a header ([hosts.box], [hosts], ["hosts".box]),
# a dotted key (hosts.box.address = ...) or an inline table (hosts = {...},
# accounts = {...}); or the configured list (private/configured.json)
# exists. Wider than needed is safe: a stand-in passes an unconfigured
# target to the user's own tool.
maybe_configured() {
  _h=$(gw_home)
  [ -f "$_h/private/configured.json" ] && return 0
  [ -f "$_h/gateway.toml" ] &&
    grep -Eq "^[[:space:]]*\\[?\\[?[[:space:]]*[\"']?(hosts|accounts)[\"']?[[:space:]]*[].=]" "$_h/gateway.toml" 2>/dev/null
}
# The same ERE for the git stub's cold pass-through (git_cold; envfile.CONFIGURED_ERE).
CONFIGURED_ERE="^[[:space:]]*\\[?\\[?[[:space:]]*[\"']?(hosts|accounts)[\"']?[[:space:]]*[].=]"

# Before Python runs SessionStart: the env file, and the stubs when one is
# missing: the full base set while something may be configured (so a
# session whose hook Claude Code cancels, its 20 s limit, or that is killed
# still runs a configured target's commands through the stand-ins), else
# only gate and the helpers (a brand-new install shadows nothing). Python
# then writes what the configured set needs (envfile.sync).
pre_session() {
  write_env_file
  if maybe_configured; then
    for n in $STUB_STANDINS $STUB_HELPERS; do
      if [ ! -f "$DATA/bin/$n" ]; then write_stubs all 2>/dev/null; break; fi
    done
  else
    for n in $STUB_HELPERS; do
      if [ ! -f "$DATA/bin/$n" ]; then write_stubs helpers 2>/dev/null; break; fi
    done
  fi
  return 0
}

# JSON string escaping for messages that carry a path.
json_esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

cleanup_envs() {
  [ -d "$DATA/envs" ] || return 0
  : > "$ENVD/.used" 2>/dev/null
  for d in "$DATA/envs"/*; do
    [ -d "$d" ] || continue
    case ${d##*/} in "$SHA"|*.*) continue ;; esac
    if [ -e "$d/.used" ]; then f="$d/.used"; else f="$d"; fi
    if [ -n "$(find "$f" -prune -mtime +7 2>/dev/null)" ]; then rm -rf "$d"; fi
  done
  return 0
}

# Load the new env once (src/gateway/warm.py): macOS checks each new binary
# and library at its first load, which cost the next session's sync
# SessionStart 5-13 s; here it costs this async hook. Marked by .warm.
warm_env() {
  [ -e "$ENVD/.warm" ] && return 0
  if "$PY" -I -S -X "pycache_prefix=$PYC" -c 'import sys; sys.path.insert(0, sys.argv[1]); from gateway import warm; sys.exit(warm.main())' \
       "$ROOT/src" </dev/null >/dev/null 2>&1; then
    : > "$ENVD/.warm" 2>/dev/null
  fi
  return 0
}

# The build lock: the folder $ENVD.building, made with mkdir (atomic), holds
# `owner`: the builder's pid, its start time (ps lstart) and host, then the
# pixi child's pid and start time. A build that was killed (SIGKILL, a crash,
# the machine slept and the hook timed out) is stale as soon as neither
# process is alive, or their pids now belong to other processes (another start
# time): waiters stop waiting and take over at once, never after a fixed
# timeout. A lock with no owner file (the instant between mkdir and writing it)
# counts as live for a minute; a lock written on another machine (a shared data
# folder; the machine is gw_hostid, stable across network names) can't be
# judged and goes stale after 30 minutes, as before.
LOCKD="$ENVD.building"

# A stable id for this machine, written into the build lock's owner so a lock
# can be judged "another host" only across machines, never across network
# names. uname -n follows the DHCP domain on macOS (Example-MBP.home one
# minute, Example-MacBook-Pro.local the next), which made a killed build on
# this machine look like one on another and stall for 30 minutes. A real
# machine id (Linux /etc/machine-id, macOS IOPlatformUUID) is stable across
# networks and reboots, so after a reboot the recorded builder is simply gone
# (its pid is dead or reused with another start time) and the lock is stale at
# once. Falls back to a boot id, then to uname -n (the old behaviour).
# Absolute tool paths only (the desktop app gives hooks a minimal PATH, so the
# id must not change with PATH: a build that recorded IOPlatformUUID must read
# back the same id from a hook that can't find ioreg on PATH).
gw_hostid() {
  _id=
  for _f in /etc/machine-id /var/lib/dbus/machine-id; do
    if [ -r "$_f" ]; then
      _id=$(tr -d '[:space:]' < "$_f" 2>/dev/null)
      [ -n "$_id" ] && { printf '%s' "$_id"; return 0; }
    fi
  done
  for _t in /usr/sbin/ioreg /sbin/ioreg; do
    if [ -x "$_t" ]; then
      _id=$("$_t" -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformUUID/{print $4; exit}')
      [ -n "$_id" ] && { printf '%s' "$_id"; return 0; }
    fi
  done
  if [ -r /proc/sys/kernel/random/boot_id ]; then
    _id=$(tr -d '[:space:]' < /proc/sys/kernel/random/boot_id 2>/dev/null)
    [ -n "$_id" ] && { printf '%s' "$_id"; return 0; }
  fi
  for _t in /usr/sbin/sysctl /sbin/sysctl; do
    if [ -x "$_t" ]; then
      _id=$("$_t" -n kern.bootsessionuuid 2>/dev/null | tr -d '[:space:]')
      [ -n "$_id" ] && { printf '%s' "$_id"; return 0; }
    fi
  done
  uname -n 2>/dev/null | tr -d '[:space:]'
}

# Sets GW_PS to "STAT START" of pid $1 ("" when ps can't tell), and
# GW_START to the start time alone, its words single-spaced ("" likewise).
gw_ps() {
  GW_PS=$(ps -o stat= -o lstart= -p "$1" 2>/dev/null) || GW_PS=
  GW_START=
  [ -n "$GW_PS" ] || return 0
  # shellcheck disable=SC2086  # split the state and the start time's words
  set -- $GW_PS
  shift
  GW_START="$*"
}

# Is pid $1 alive and still the process that started at $2 ("" = unknown)?
gw_alive() {
  case $1 in ''|*[!0-9]*) return 1 ;; esac
  kill -0 "$1" 2>/dev/null || return 1
  gw_ps "$1"
  [ -n "$GW_PS" ] || return 0                    # ps can't tell: kill -0 says alive
  case $GW_PS in Z*|' 'Z*) return 1 ;; esac      # a zombie: dead, not reaped yet
  [ -z "$2" ] || [ "$GW_START" = "$2" ]          # else the pid was reused
}

# Writes the owner file: this shell, and the pixi child when $1 is given.
gw_owner() {
  _c=${1-}
  gw_ps $$
  _me=$GW_START
  {
    printf 'pid=%s\nstart=%s\nhost=%s\n' "$$" "$_me" "$(gw_hostid)"
    if [ -n "$_c" ]; then
      gw_ps "$_c"
      printf 'child=%s\ncstart=%s\n' "$_c" "$GW_START"
    fi
  } > "$LOCKD/.owner.$$" 2>/dev/null && mv -f "$LOCKD/.owner.$$" "$LOCKD/owner" 2>/dev/null
}

# Is the build lock held by a live builder? (No lock: no.)
lock_live() {
  [ -d "$LOCKD" ] || return 1
  if [ ! -f "$LOCKD/owner" ]; then
    [ -z "$(find "$LOCKD" -prune -mmin +1 2>/dev/null)" ]
    return $?
  fi
  _pid= _start= _host= _child= _cstart=
  while IFS='=' read -r _k _v; do
    case $_k in
      pid) _pid=$_v ;; start) _start=$_v ;; host) _host=$_v ;;
      child) _child=$_v ;; cstart) _cstart=$_v ;;
    esac
  done < "$LOCKD/owner"
  if [ -n "$_host" ] && [ "$_host" != "$(gw_hostid)" ]; then
    [ -z "$(find "$LOCKD" -prune -mmin +30 2>/dev/null)" ]
    return $?
  fi
  gw_alive "$_pid" "$_start" && return 0
  [ -n "$_child" ] && gw_alive "$_child" "$_cstart" && return 0
  return 1
}

# Moves a stale lock out of the way (rename first, so two waiters can't both
# remove it), then deletes it. False when it is still there.
break_lock() {
  _t="$LOCKD.stale.$$"
  if mv "$LOCKD" "$_t" 2>/dev/null; then rm -rf "$_t"; return 0; fi
  [ ! -d "$LOCKD" ]
}

ensure_env() {
  # an env built by a setup that was interrupted before managed_sync ran: its
  # settings first (gate-sh refuses commands until they exist), then the rest
  if ready; then [ -f "$DATA/managed/conf" ] || managed_sync; warm_env; cleanup_envs; return 0; fi
  P=$(find_pixi) || { echo "gateway: pixi isn't installed (https://pixi.sh)" >&2; return 1; }
  mkdir -p "$ENVD" || return 1
  i=0
  while ! mkdir "$LOCKD" 2>/dev/null; do
    [ -d "$LOCKD" ] || return 1                  # can't make it at all
    if ! lock_live; then                         # the builder died: take over
      break_lock || return 1
      continue
    fi
    [ "$i" -lt 900 ] || return 1
    sleep 2
    i=$((i + 2))
    if [ ! -d "$LOCKD" ]; then                   # the builder finished
      ready
      return $?
    fi
  done
  # Ours. A normal exit removes the lock; a signal leaves it with this dead
  # owner, so a waiter takes over at once (and the pixi child is stopped).
  cpid=
  gw_owner
  trap 'rm -rf "$LOCKD"' EXIT
  trap 'trap - EXIT; [ -n "$cpid" ] && kill "$cpid" 2>/dev/null; exit 143' HUP INT TERM
  rc=1
  rm -f "$ENVD/.pixi-too-old"
  if cp "$ROOT/pixi.toml" "$ROOT/pixi.lock" "$ENVD/"; then
    "$P" install --locked --manifest-path "$ENVD/pixi.toml" > "$ENVD/install.log" 2>&1 &
    cpid=$!
    gw_owner "$cpid"
    wait "$cpid"
    prc=$?
    cpid=
    if [ "$prc" -eq 0 ] && [ -x "$PY" ]; then
      : > "$ENVD/.ready"
      rc=0
    else
      note_pixi_too_old "$P"
    fi
  fi
  rm -rf "$LOCKD"
  trap - EXIT HUP INT TERM
  # the managed shell's settings before the warm-up: gate-sh refuses commands
  # until they exist, and warming a new env takes seconds on macOS (status
  # reports "managed" so the mod's status line says ready only after them)
  [ "$rc" -eq 0 ] && { managed_sync; warm_env; cleanup_envs; }
  return "$rc"
}

# The managed shell's files (src/gateway/managed.py) as soon as an env can
# run Python: a first session's SessionStart ran before the env existed, and
# hooks/gate-sh refuses to run anything until they are written. --setup:
# first a missing gateway.toml as SessionStart writes it (the starter form on
# a new install), so it is there when setup says ready, not only from the
# next session on. Async (this hook or the mod's spawn), after the build
# lock is gone; the form is linked into place whole.
managed_sync() {
  [ -n "${GATEWAY_TEST_ROOT-}" ] && return 0
  "$PY" -I -S -X "pycache_prefix=$PYC" "$ROOT/run.py" managed-sync --setup </dev/null >/dev/null 2>&1
  return 0
}

build_failed() {
  # An attempt left its log but no .ready, and no live build is running now
  # (a killed one's lock is stale: lock_live).
  [ -f "$ENVD/install.log" ] && [ ! -e "$ENVD/.ready" ] && ! lock_live
}

# pixi refused the manifest because it is older than requires-pixi ("this
# project requires pixi '>=0.83.0', but you have pixi 0.81.0"): the versions
# go to $ENVD/.pixi-too-old, two key=value lines (found=, needed=) that
# status, the not-ready texts and gate status read. Each sed takes the words,
# each tr keeps only version characters of them (no quote, backslash or $
# reaches the JSON or sh texts). The next build attempt removes it.
note_pixi_too_old() {
  _l=$(grep "requires pixi '" "$ENVD/install.log" 2>/dev/null | head -n 1)
  [ -n "$_l" ] || return 0
  _need=$(printf '%s\n' "$_l" | sed -n "s/.*requires pixi '\([^']*\)'.*/\1/p" | tr -cd '0-9A-Za-z.,<>=!*~ ')
  _have=$(printf '%s\n' "$_l" | sed -n 's/.*you have pixi \([0-9][^ ,]*\).*/\1/p' | tr -cd '0-9A-Za-z.+-')
  [ -n "$_have" ] || _have=$("$1" --version 2>/dev/null | head -n 1 | sed -n 's/[^0-9]*\([0-9][^ ]*\).*/\1/p' | tr -cd '0-9A-Za-z.+-')
  if printf 'found=%s\nneeded=%s\n' "$_have" "$_need" > "$ENVD/.pixi-too-old.$$"; then
    mv -f "$ENVD/.pixi-too-old.$$" "$ENVD/.pixi-too-old"
  else
    rm -f "$ENVD/.pixi-too-old.$$"
  fi
}

# Is the last build's failure pixi's "requires pixi" refusal? Sets GW_TOOOLD
# to the words the not-ready texts use ("pixi 0.81.0 is too old (the gateway
# needs pixi >=0.83.0)"; envfile.pixi_too_old_words), and GW_PFOUND and
# GW_PNEED to the versions.
pixi_too_old() {
  GW_PFOUND= GW_PNEED= GW_TOOOLD=
  [ -f "$ENVD/.pixi-too-old" ] && build_failed || return 1
  while IFS='=' read -r _k _v; do
    case $_k in found) GW_PFOUND=$_v ;; needed) GW_PNEED=$_v ;; esac
  done < "$ENVD/.pixi-too-old"
  if [ -n "$GW_PFOUND" ]; then GW_TOOOLD="pixi $GW_PFOUND is too old"; else GW_TOOOLD="this pixi is too old"; fi
  [ -z "$GW_PNEED" ] || GW_TOOOLD="$GW_TOOOLD (the gateway needs pixi $GW_PNEED)"
  return 0
}

# What a stand-in says while the gateway can't run, by state: pixi missing,
# the build failed (retried only at the next session start), or building.
not_ready_text() {
  if ! find_pixi >/dev/null 2>&1; then
    printf '%s' "$NOPIXI"
  elif pixi_too_old; then
    printf '%s' "gateway: the gateway can't set itself up: $GW_TOOOLD; tell the user to update pixi ($GW_PIXI_UPDATE) and start a new session"
  elif build_failed; then
    printf '%s' "gateway: the gateway's setup failed (log: $ENVD/install.log); it is retried at the next session start; tell the user"
  else
    printf '%s' "$STILL"
  fi
}

# The launcher's text by the same states (envfile.launcher_not_ready).
launcher_not_ready_text() {
  if ! find_pixi >/dev/null 2>&1; then
    printf '%s' "$LNOPIXI"
  elif pixi_too_old; then
    printf '%s' "gateway: the gateway can't set itself up: $GW_TOOOLD; update pixi ($GW_PIXI_UPDATE), then start a new Claude Code session"
  elif build_failed; then
    printf '%s' "gateway: the gateway's setup failed (log: $ENVD/install.log); start a new Claude Code session to retry"
  else
    printf '%s' "$STILL"
  fi
}

# Claude's context while the gateway can't run, by the same states.
not_ready_context() {
  tail="until then the gateway's commands for the machines and accounts in gateway.toml (ssh, gh, gate, ...) refuse, so don't retry them; anything else uses the user's own tools. Never ask the user for a password, token or key in chat."
  if ! find_pixi >/dev/null 2>&1; then
    printf '%s' "Gateway (plugin): the gateway can't set itself up because pixi isn't installed. Tell the user once to install it from https://pixi.sh and start a new session; $tail"
  elif pixi_too_old; then
    printf '%s' "Gateway (plugin): the gateway can't set itself up: $(json_esc "$GW_TOOOLD"). Tell the user once to update pixi ($GW_PIXI_UPDATE) and start a new session; $tail"
  elif build_failed; then
    printf '%s' "Gateway (plugin): the gateway's first-time setup failed (log: $(json_esc "$ENVD/install.log")); it is retried at the next session start. Tell the user once; $tail"
  else
    printf '%s' "Gateway (plugin): first-time setup is still running. The gateway's commands for the machines and accounts in gateway.toml (ssh, gh, ...) say they are still setting up until it finishes (about a minute); anything else uses the user's own tools. Never ask the user for a password, token or key in chat."
  fi
}

degraded_session() {
  LSTILL=$(launcher_not_ready_text)
  STILL=$(not_ready_text)
  write_env_file
  if maybe_configured; then
    write_stubs all 2>/dev/null
  else
    write_stubs helpers 2>/dev/null
  fi
  write_launcher 2>/dev/null
  if ! find_pixi >/dev/null 2>&1; then
    msg="gateway: pixi isn't installed, so the gateway can't set itself up. Install it from https://pixi.sh, then start a new session."
  elif pixi_too_old; then
    msg="gateway: the gateway can't set itself up: $(json_esc "$GW_TOOOLD"). Update pixi ($GW_PIXI_UPDATE), then start a new session."
  elif build_failed; then
    msg="gateway: setting up failed; see $(json_esc "$ENVD/install.log") (it is retried at every session start)"
  else
    msg="gateway: first-time setup is running (about a minute); then restart the session (or reconnect gw in /mcp) for the http tool"
  fi
  ctx=$(not_ready_context)
  printf '{"systemMessage": "%s", "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "%s"}}\n' "$msg" "$ctx"
}

# Lowercase, trailing slashes removed, ~ expanded.
norm_path() {
  p=$1
  # shellcheck disable=SC2088  # a literal ~ from the payload
  case $p in "~"|"~/"*) p="${HOME:-}${p#\~}" ;; esac    # Claude Code's own meaning of ~
  while :; do
    case $p in /) break ;; */) p=${p%/} ;; *) break ;; esac
  done
  printf '%s' "$p" | tr '[:upper:]' '[:lower:]'
}

# The JSON string value of "KEY" in a (lowercased) hook payload.
json_str() {
  printf '%s' "$2" | sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

# Is $1 (normalized) a protected location or a folder above one?
above_protected() {
  [ -n "$1" ] || return 1
  [ "$1" = / ] && return 0
  uid=$(id -u 2>/dev/null || echo x)
  for t in "$(norm_path "$UHOME/.config/gateway/private")" \
           "$(norm_path "$UHOME/.config/gateway/key.txt")" \
           "$(norm_path "${HOME:-/nonexistent}/.config/gateway/private")" \
           "$(norm_path "${HOME:-/nonexistent}/.config/gateway/key.txt")" \
           "/tmp/gw-$uid" "/private/tmp/gw-$uid"; do
    case "$t/" in "$1"/*) return 0 ;; esac
  done
  return 1
}

# Is $1 (normalized) at or above a Claude Code transcripts folder (a recursive
# search from it would read session transcripts under .claude/projects or
# .config/claude/projects)? Python's hooks_files uses the resolved roots; the
# cold guard compares the two well-known trees as text (it is the reduced form).
above_transcripts() {
  [ -n "$1" ] || return 1
  [ "$1" = / ] && return 0
  for t in "$(norm_path "$UHOME/.claude/projects")" \
           "$(norm_path "$UHOME/.config/claude/projects")" \
           "$(norm_path "${HOME:-/nonexistent}/.claude/projects")" \
           "$(norm_path "${HOME:-/nonexistent}/.config/claude/projects")"; do
    case "$t/" in "$1"/*) return 0 ;; esac
  done
  return 1
}

# Does one (lowercased) path field point into a protected location? Relative
# paths are taken from the cwd; `..` anywhere near the gateway counts.
field_inside() {
  f=$1
  [ -n "$f" ] || return 1
  case $f in /*|"~"*) ;; *) f="$2/$f" ;; esac
  f=$(norm_path "$f")
  case $f in
    *"gateway/private"*|*"gateway/key.txt"*|*"gateway/store.age"*|*"/tmp/gw-"*) return 0 ;;
    *"/.."*) case $f in *gateway*|*"/gw-"*|*".config"*) return 0 ;; esac ;;
  esac
  return 1
}

# Does one (lowercased) path field name a Claude Code session transcript: a
# `.jsonl` under a `projects/` folder, but not inside a tool-results folder and
# not a Workflow run's journal.jsonl (both readable, as Python's is_transcript
# allows)? Relative paths are taken from the cwd.
field_transcript() {
  f=$1
  [ -n "$f" ] || return 1
  case $f in /*|"~"*) ;; *) f="$2/$f" ;; esac
  f=$(norm_path "$f")
  case $f in *.jsonl) ;; *) return 1 ;; esac
  case $f in
    */subagents/workflows/*/journal.jsonl) return 1 ;;
    */tool-results/*) return 1 ;;
  esac
  case $f in */projects/*) return 0 ;; esac
  return 1
}

# The file guard while the env builds (Python's hooks_files does it properly):
# case-insensitive checks of the tool's path fields for the protected
# locations, `..` near the gateway home, and Grep/Glob from a folder above a
# protected location. Only path fields are looked at (an Edit whose text
# merely mentions ~/.config/gateway/private is fine).
degraded_files() {
  payload=$GW_PAYLOAD
  lower=$(printf '%s' "$payload" | tr '[:upper:]' '[:lower:]')
  cwd=$(json_str cwd "$lower")
  deny=""
  # The desktop app's session tools (hooks_files.py): never an export.
  case $lower in
    *'"tool_name":"mcp__ccd_session_mgmt__export_transcript"'*|*'"tool_name": "mcp__ccd_session_mgmt__export_transcript"'*)
      deny="export" ;;
  esac
  keys="file_path path notebook_path"
  case $lower in *'"tool_name":"glob"'*|*'"tool_name": "glob"'*) keys="$keys pattern" ;; esac
  [ -n "$deny" ] || for k in $keys; do
    if field_inside "$(json_str "$k" "$lower")" "$cwd"; then deny=inside; fi
  done
  # Session transcripts read through the Read/Edit tools (a .jsonl under
  # */projects/): Python's hooks_files denies them, so the cold guard must too
  # (the cold Bash path already refuses them; this closes the Read/Grep route).
  [ -n "$deny" ] || for k in file_path notebook_path path; do
    if field_transcript "$(json_str "$k" "$lower")" "$cwd"; then deny=transcript; fi
  done
  if [ -z "$deny" ]; then
    case $lower in
      *'"tool_name":"grep"'*|*'"tool_name": "grep"'*)
        p=$(json_str path "$lower")
        [ -n "$p" ] || p=$cwd
        case $p in /*|"~"*) ;; *) p="$cwd/$p" ;; esac
        np=$(norm_path "$p")
        if above_protected "$np"; then deny=parent
        elif above_transcripts "$np"; then deny=transcript_search; fi ;;
    esac
  fi
  case $deny in
    inside) printf '%s\n' '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "gateway: that path holds the gateway private keys and vault; Claude never needs it."}}' ;;
    parent) printf '%s\n' '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "gateway: that search would also read the gateway private keys and vault (under ~/.config/gateway); search a narrower folder, such as the project, instead."}}' ;;
    transcript) printf '%s\n' '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "gateway: that is a Claude Code session transcript; it can hold output Claude Code showed unmasked (a failed command'\''s, a background command'\''s notice), so Claude doesn'\''t read it (the tool-results folder next to it, and a Workflow run'\''s journal.jsonl, are fine)."}}' ;;
    transcript_search) printf '%s\n' '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "gateway: that search would read Claude Code'\''s session transcripts (they can hold output Claude Code showed unmasked); search a narrower folder, or a Workflow run'\''s journal.jsonl itself, instead."}}' ;;
    export) printf '%s\n' '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "gateway: exporting a session transcript is off while the gateway is installed (transcripts can hold unmasked output); if the user wants an export, they can make it themselves."}}' ;;
  esac
  return 0
}

# The gateway home (where the form and the vault live), as the other degraded
# paths see it.
gw_home() {
  if [ -n "$GW_E2E_ROOT" ]; then printf '%s' "$GW_E2E_ROOT/home/.config/gateway"
  else printf '%s' "$UHOME/.config/gateway"; fi
}

# The Bash approval hook while no env can run Python (PLAN-v4 phase 1; brief
# section 2: a cold start must not switch security controls off). Python's
# hooks_bash decides in full once the env is ready; until then this denies,
# by text, what it can recognize in sh: reads of the gateway's private folder
# (and of ~/.config/gateway other than gateway.toml), session transcripts,
# credential helpers / age -d / access tokens / token-bearing command lines.
# The network class (PLAN-0.11 §3.4) is asked about, or denied while
# gateway.toml has a [network] table (sh can't read its value). Everything
# else gets no decision (Claude Code's own permissions apply). It reads only
# what pre_bash.sh forwards (its trigger words), like the Python hook. Its
# lines are byte-identical to envfile.degraded_bash_text(KIND) (tests compare
# them).
DEG_HEAD="gateway: still setting up (first run), so its guard works in a reduced form:"
DEG_TAIL="is refused until setup finishes (about a minute; if it can't finish, the session's first gateway message says why)."
DEG_ASK_TAIL="is asked about until setup finishes (about a minute; if it can't finish, the session's first gateway message says why)."
degraded_bash_text() {
  _d=deny; _t=$DEG_TAIL
  case $1 in
    private) _w="anything naming the gateway's private folder, keys or vault (~/.config/gateway other than gateway.toml)" ;;
    transcript) _w="reading Claude Code's session transcripts" ;;
    cred) _w="running a credential helper, decrypting with age, printing an access token or passing a token on the command line" ;;
    network) _w="running a network command (curl, wget, nc, nmap, ...)"; _d=ask; _t=$DEG_ASK_TAIL ;;
    network_table) _w="running a network command (curl, wget, nc, nmap, ...; gateway.toml's [network] table can't be read until then)" ;;
  esac
  printf '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "%s", "permissionDecisionReason": "%s %s %s"}}\n' "$_d" "$DEG_HEAD" "$_w" "$_t"
}

DEG_SHAPES='gh[pousr]_[A-Za-z0-9_]{10,}|github_pat_[A-Za-z0-9_]{10,}|hf_[A-Za-z0-9]{10,}|glpat-[A-Za-z0-9_-]{10,}|sk-[A-Za-z0-9_-]{16,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}|AGE-SECRET-KEY-1|-----BEGIN [A-Z0-9 ]*PRIVATE KEY|[Aa]uthorization: *([Bb]earer|[Bb]asic|[Tt]oken) '
DEG_PRIVATE='gateway/private|gateway/key\.txt|gateway/store\.age|/tmp/gw-|(^|[^a-z0-9_-])(key\.txt|vault\.age|cache\.age|store\.age)([^a-z0-9_.-]|$)'
# A glob (*, ?, [ or ]) inside the path segment right after .config/, e.g.
# .config/gate* or .config/*/private: the shell could expand it to the gateway
# folder, so it is treated as naming it (quotes already stripped by _dq).
DEG_PRIVATE_GLOB='\.config/[^/[:space:]]*[][*?]'
# The parent-folder rule's two halves, like the transcript side's DEG_TREE:
# the text names .config (~/.config, $HOME/.config, bounded) together with the
# word gateway / gate* (so a separated `-C ~/.config gateway` is caught), or
# together with a recursive reader or archiver (DEG_TREE: `tar -C ~/.config .`
# archives the private folder without ever spelling its name).
DEG_CONFIG='(^|[^a-z0-9_])\.config([^a-z0-9_.-]|$)'
DEG_GATEWORD='(^|[^a-z0-9_-])gate(way|[][*?])'
DEG_TREE='(^|[^a-z0-9_-])(-[a-z]*r[a-z]*|--recursive|-a|--archive|tar|zip|rsync|rg|ag|find|cp|scp)([^a-z0-9_-]|$)'
DEG_CRED='git_trace_redact|git-credential|gate-askpass|get-access-token|(^|[^a-z0-9_-])git([[:space:]]+(-[cC][[:space:]]+[^[:space:]]+|-[^[:space:]]+))*[[:space:]]+credential([^a-z0-9_-]|$)|(^|[^a-z0-9_.-])age[[:space:]][^|;&]*(-d|--decrypt)([^a-z0-9_-]|$)'
# The network class (PLAN-0.11 §3.1), as pre_bash.sh reads it: its names
# (DEG_NET_NAMES is form.NETWORK_BUILTIN; a test compares the lists) and the
# user's `extra` names from $DATA/network-words, never glued to a dot, a dash
# or a colon after them; the structural members by their shapes (openssl's
# TLS client and server, an HTTP server, a busybox applet, rsync to a
# daemon, /dev/tcp and /dev/udp). Matched on the payload with JSON's \n, \r
# and \t made spaces and quotes and backslashes dropped, without letter case
# (macOS's file systems ignore it: CURL runs curl), but php's server flag
# keeps its case (-S; DEG_NET_PHP).
DEG_NET_NAMES='curl|wget|wget2|aria2c|xh|http|https|lynx|w3m|links|links2|nmap|nping|masscan|zmap|rustscan|hping3|ssh-keyscan|nc|ncat|netcat|socat|telnet|ftp|tftp|lftp|smbclient|certutil|tcpdump|tshark|nikto|sqlmap|hydra|gobuster|ffuf|nuclei|arp-scan|iperf3'
DEG_NET_SHAPES='/dev/(tcp|udp)/|(^|[^A-Za-z0-9_.-])openssl[[:space:]]+s_(client|server|time)([^A-Za-z0-9_]|$)|-[A-Za-z]*m[[:space:]]*(http\.server|SimpleHTTPServer|http)([^A-Za-z0-9_.]|$)|-run[[:space:]]+-e[[:space:]]*httpd|(^|[^A-Za-z0-9_.-])busybox[[:space:]]+httpd|(^|[^A-Za-z0-9_.-])rsync[[:space:]][^;&|]*(rsync://|[^/:[:space:]]::)'
DEG_NET_PHP='(^|[^A-Za-z0-9_.-])[Pp][Hh][Pp][0-9.]*[[:space:]]([^;&|]*[[:space:]])?-S'
# A [network] table in gateway.toml (a header [network] or [network.x], or a
# top-level network key before the first header).
gw_network_table() {
  [ -f "$1" ] && awk '/^[[:space:]]*\[[[:space:]]*"?network"?[[:space:]]*[].]/ { f = 1 }
    /^[[:space:]]*\[/ { t = 1 }
    !t && /^[[:space:]]*"?network"?[[:space:]]*[.=]/ { f = 1 }
    END { exit !f }' "$1" 2>/dev/null
}

degraded_bash() {
  # The payload without its transcript paths and cwd (they name Claude's own
  # folders on every call), as the prefilter does.
  _raw=$(printf '%s' "$GW_PAYLOAD" | sed 's/"[a-z_]*transcript_path"[[:space:]]*:[[:space:]]*"[^"]*"//g; s/"cwd"[[:space:]]*:[[:space:]]*"[^"]*"//g')
  _lt=$(printf '%s' "$_raw" | tr '[:upper:]' '[:lower:]')
  # Drop quotes and backslashes so gate""way and gate\way read as gateway, then
  # the literal spellings, a glob just after .config/, and the parent rule all
  # see the real path. gateway.toml alone (the form) stays readable.
  _dq=$(printf '%s' "$_lt" | tr -d "\"'\\\\")
  # Transcripts (under .config/claude or .claude) come first, so a recursive
  # read of ~/.config/claude/projects is reported as a transcript, not caught
  # by the .config parent rule below (which guards ~/.config/gateway).
  _nj=$(printf '%s' "$_lt" | sed 's#/subagents/workflows/[^/"[:space:]]*/journal\.jsonl##g')
  if { printf '%s' "$_nj" | grep -q -- '\.jsonl' && printf '%s' "$_nj" | grep -q -- 'projects/'; } ||
     printf '%s' "$_lt" | grep -Eq -- '(\.claude|/claude)/projects/?([^a-z0-9_./-]|$)' ||
     { printf '%s' "$_lt" | grep -Eq -- '(\.claude|\.config/claude)/?([^a-z0-9_./-]|$)' &&
       printf '%s' "$_lt" | grep -Eq -- "$DEG_TREE"; }; then
    degraded_bash_text transcript; return 0
  fi
  _np=$(printf '%s' "$_dq" | sed 's#\.config/gateway/gateway\.toml##g')
  if printf '%s' "$_np" | grep -Eq -- "$DEG_PRIVATE" ||
     printf '%s' "$_np" | grep -Eq -- "$DEG_PRIVATE_GLOB" ||
     { printf '%s' "$_np" | grep -Eq -- "$DEG_CONFIG" &&
       { printf '%s' "$_np" | grep -Eq -- "$DEG_GATEWORD" ||
         printf '%s' "$_np" | grep -Eq -- "$DEG_TREE"; }; }; then
    degraded_bash_text private; return 0
  fi
  if printf '%s' "$_lt" | grep -Eq -- "$DEG_CRED" || printf '%s' "$_raw" | grep -Eq -- "$DEG_SHAPES"; then
    degraded_bash_text cred; return 0
  fi
  _names=$DEG_NET_NAMES
  if [ -f "$DATA/network-words" ]; then
    while IFS= read -r _x || [ -n "$_x" ]; do
      case $_x in ''|*[!A-Za-z0-9._-]*) continue ;; esac
      _e=; _r=$_x
      while :; do
        case $_r in
          *.*) _e="$_e${_r%%.*}\\."; _r=${_r#*.} ;;
          *) _e="$_e$_r"; break ;;
        esac
      done
      _names="$_names|$_e"
    done < "$DATA/network-words"
  fi
  _dn=$(printf '%s' "$_raw" | sed -e 's/\\[nrt]/ /g' -e "s/[\"'\\\\]//g")
  if printf '%s' "$_dn" | grep -Eiq -- "(^|[^A-Za-z0-9_.-])($_names)([^A-Za-z0-9_.:-]|\$)|$DEG_NET_SHAPES" ||
     printf '%s' "$_dn" | grep -Eq -- "$DEG_NET_PHP"; then
    _h=$(gw_home)
    if gw_network_table "$_h/gateway.toml"; then
      degraded_bash_text network_table
    else
      degraded_bash_text network
    fi
    return 0
  fi
  return 0
}

if [ "$mode" = ensure-env ]; then
  ensure_env
  exit $?
fi

# launch.sh status [--test] [pixi]: one JSON line for the mod's status line
# and /gate-doctor. Looks, never builds and never reads the vault: the vault
# and the form are only tested for existence. "pixi" adds `pixi --version`.
jb() { if "$@"; then printf true; else printf false; fi; }
if [ "$mode" = status ]; then
  _pixi=$(find_pixi 2>/dev/null) || _pixi=
  if ready; then _state=ready
  elif [ -z "$_pixi" ]; then _state=nopixi
  elif lock_live; then _state=building
  elif build_failed; then _state=failed
  else _state=missing; fi
  _pv=
  case " $* " in *" pixi "*)
    [ -n "$_pixi" ] && _pv=$("$_pixi" --version 2>/dev/null | head -n 1) ;;
  esac
  _old=$(older_env)
  _h=$(gw_home)
  # pixi_too_old: the last build failed on pixi's "requires pixi" refusal,
  # with the pixi it found and the requires-pixi it needs
  _too=false GW_PFOUND= GW_PNEED=
  if [ "$_state" = failed ] && pixi_too_old; then _too=true; fi
  # vault: the vault (private/vault.age; existence only, never read).
  # managed: the managed shell's settings are written (gate-sh runs nothing before)
  printf '{"state": "%s", "root": "%s", "data": "%s", "env": "%s", "lock": "%s", "warm": %s, "managed": %s, "older": "%s", "build_running": %s, "install_log": %s, "pixi": "%s", "pixi_version": "%s", "pixi_too_old": %s, "pixi_found": "%s", "pixi_needed": "%s", "home": "%s", "form": %s, "vault": %s}\n' \
    "$_state" "$(json_esc "$ROOT")" "$(json_esc "$DATA")" "$(json_esc "$ENVD")" "$SHA" \
    "$(jb test -e "$ENVD/.warm")" "$(jb test -f "$DATA/managed/conf")" "$(json_esc "$_old")" "$(jb lock_live)" "$(jb test -f "$ENVD/install.log")" \
    "$(json_esc "$_pixi")" "$(json_esc "$_pv")" "$_too" "$(json_esc "$GW_PFOUND")" "$(json_esc "$GW_PNEED")" "$(json_esc "$_h")" \
    "$(jb test -f "$_h/gateway.toml")" "$(jb test -e "$_h/private/vault.age")"
  exit 0
fi

# run_py PYTHON ARGS...: run.py ARGS... (the file guard's payload was read
# already, for the fast path: it goes to Python on stdin, and run.py's exit
# status, 2 when the guard fails, is this script's).
run_py() {
  _py=$1
  shift
  if [ "$mode" = hook-files ]; then
    printf '%s\n' "$GW_PAYLOAD" | "$_py" -I -S -X "pycache_prefix=$PYC" "$ROOT/run.py" "$@"
    exit $?
  fi
  exec "$_py" -I -S -X "pycache_prefix=$PYC" "$ROOT/run.py" "$@"
}

if ready; then
  if [ "$mode" = hook-session ]; then
    : > "$ENVD/.used" 2>/dev/null
    pre_session
  fi
  run_py "$PY" "$@"
fi

case $mode in
  hook-*|mcp)
    OLD=$(older_env)
    if [ -n "$OLD" ]; then
      : > "$OLD/.used" 2>/dev/null          # in use: kept by cleanup_envs
      [ "$mode" = hook-session ] && pre_session
      run_py "$OLD/.pixi/envs/default/bin/python3" "$@"
    fi ;;
esac

case $mode in
  hook-session) degraded_session ;;
  hook-subagent)
    printf '{"hookSpecificOutput": {"hookEventName": "SubagentStart", "additionalContext": "%s"}}\n' "$(not_ready_context)" ;;
  hook-files) degraded_files ;;
  hook-bash) GW_PAYLOAD=$(cat); degraded_bash ;;
  hook-*) cat > /dev/null 2>&1 ;;
  mcp)
    i=0
    while [ "$i" -lt 4 ]; do
      sleep 1
      i=$((i + 1))
      if ready; then exec "$PY" -I -S -X "pycache_prefix=$PYC" "$ROOT/run.py" "$@"; fi
    done
    not_ready_text >&2; echo >&2
    exit 1 ;;
  *) not_ready_text >&2; echo >&2; exit 75 ;;
esac
exit 0
