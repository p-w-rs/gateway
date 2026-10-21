# Sourced by launch.sh, prompt.sh and post.sh (POSIX sh; defines functions only).
#
# The e2e suite's redirection (tests/e2e/README.md), with the same rules as
# paths.e2e_marker on the Python side, so the sh hooks and Python always agree:
#
#   gw_e2e PLUGIN_DIR    sets GW_E2E_ROOT and GW_E2E_RUN (maybe empty) and
#                        returns 0 only when
#     - PLUGIN_DIR (taken physically) is owned by this user and lies under a
#       temp folder (/tmp, /var/tmp, macOS /var/folders, their /private forms);
#     - PLUGIN_DIR/e2e-root is a regular file (not a symlink) owned by this
#       user, not writable by group or others, holding one or two non-blank
#       lines, each an absolute path of [A-Za-z0-9/._-] characters;
#     - each of those is a real directory (not a symlink) owned by this user
#       with no group/other permission bits, whose physical path lies under a
#       temp folder.
#
# Production has no marker: one failed `[ -f ]`, nothing set, every hook
# behaves as before. A checkout or an installed plugin never lies under a temp
# folder, so a marker written there is ignored.

gw_e2e_tmp() {
  case $1 in *[!A-Za-z0-9/._-]*|*/../*|*/..|*/./*|*/.|*//*) return 1 ;; esac
  case $1/ in
    /tmp/?*|/private/tmp/?*|/var/tmp/?*|/private/var/tmp/?*|/var/folders/?*|/private/var/folders/?*) return 0 ;;
  esac
  return 1
}

# A folder named by the marker; prints its physical path.
gw_e2e_dir() {
  gw_e2e_tmp "$1" || return 1
  [ -d "$1" ] && [ ! -L "$1" ] && [ -O "$1" ] || return 1
  [ -z "$(find "$1" -prune \( -perm -040 -o -perm -020 -o -perm -010 -o -perm -004 -o -perm -002 -o -perm -001 \) -print 2>/dev/null)" ] || return 1
  _gd=$(CDPATH='' cd -- "$1" 2>/dev/null && pwd -P) || return 1
  gw_e2e_tmp "$_gd" || return 1
  printf '%s' "$_gd"
}

gw_e2e() {
  GW_E2E_ROOT=
  GW_E2E_RUN=
  case ${1-} in /*) ;; *) return 1 ;; esac
  [ -f "$1/e2e-root" ] || return 1
  _gp=$(CDPATH='' cd -- "$1" 2>/dev/null && pwd -P) || return 1
  gw_e2e_tmp "$_gp" && [ -O "$_gp" ] || return 1
  _gm="$_gp/e2e-root"
  [ -f "$_gm" ] && [ ! -L "$_gm" ] && [ -O "$_gm" ] || return 1
  [ -z "$(find "$_gm" -prune \( -perm -020 -o -perm -002 \) -print 2>/dev/null)" ] || return 1
  _gl=$(sed -n '/[^[:space:]]/p' "$_gm" 2>/dev/null) || return 1
  _gr=$(printf '%s\n' "$_gl" | sed -n 1p)
  _gu=$(printf '%s\n' "$_gl" | sed -n 2p)
  [ -z "$(printf '%s\n' "$_gl" | sed -n 3p)" ] || return 1
  _gr=$(gw_e2e_dir "$_gr") || return 1
  if [ -n "$_gu" ]; then
    _gu=$(gw_e2e_dir "$_gu") || return 1
  fi
  GW_E2E_ROOT=$_gr
  GW_E2E_RUN=$_gu
  return 0
}
