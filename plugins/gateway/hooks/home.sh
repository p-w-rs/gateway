# Sourced by launch.sh, prompt.sh and post.sh (POSIX sh; defines functions only).
#
#   gw_user_home    prints the user's home from the password database, the same
#                   folder as paths.user_home() in Python, never $HOME: Claude
#                   Code may run with HOME pointing elsewhere (a separate HOME
#                   for isolation, some containers and devboxes), while every
#                   gateway process keeps the vault in the passwd home. When the
#                   database gives nothing usable (a login name the shell can't
#                   expand), $HOME is the fallback, then /nonexistent.
#
# Review round 4: post.sh decided "a vault exists" from $HOME, so with HOME set
# elsewhere stored values without a token shape reached Claude unmasked.

gw_user_home() {
  _gwu=$(id -un 2>/dev/null) || _gwu=
  _gwh=
  case $_gwu in
    ''|-*|*[!A-Za-z0-9._-]*) ;;
    *) eval "_gwh=~$_gwu" ;;          # tilde expansion looks the name up (getpwnam)
  esac
  case $_gwh in
    /*) ;;
    *) _gwh=${HOME:-/nonexistent}
       case $_gwh in /*) ;; *) _gwh=/nonexistent ;; esac ;;
  esac
  printf '%s' "$_gwh"
}
