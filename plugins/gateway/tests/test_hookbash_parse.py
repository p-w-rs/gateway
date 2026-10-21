"""bashparse.parse: the conservative splitter (SPEC 8)."""
from __future__ import annotations

from gateway import bashparse as B


def test_simple_and_chains_and_pipes():
    assert B.parse("sudo apt install htop") == [[["sudo", "apt", "install", "htop"]]]
    assert B.parse("a && b || c; d") == [[["a"]], [["b"]], [["c"]], [["d"]]]
    assert B.parse("ssh h df | head") == [[["ssh", "h", "df"], ["head"]]]
    assert B.parse("ls\ncat f") == [[["ls"]], [["cat", "f"]]]


def test_quotes_keep_words_together():
    assert B.parse("echo 'curl http://x'") == [[["echo", "curl http://x"]]]
    assert B.parse('echo "a b c"') == [[["echo", "a b c"]]]
    assert B.parse("echo a'b'c") == [[["echo", "abc"]]]


def test_giveup_on_substitution_and_eval():
    for cmd in ("echo $(id)", "echo `id`", "eval ls", "exec sh", "source x", ". ./x",
                "sh -c 'ls'", "bash -c x", "zsh -c x", "cat <(ls)", "echo >(cat)",
                "cmd << EOF\nhi\nEOF", "cmd <<< hi", "(subshell)", "foo() { ls; }",
                "ls &", "ls & echo done"):
        assert B.parse(cmd) is None, cmd


def test_assignment_prefixes():
    assert B.parse("GATE_ACCOUNT=work gh pr") == [[["GATE_ACCOUNT=work", "gh", "pr"]]]
    assert B.parse("A=1 ls") is None
    assert B.parse("A=1 B=2 ls") is None
    assert B.parse("GATE_ACCOUNT=x GIT_TRACE_REDACT=0 git") is None
    # an assignment that is not a prefix (a normal arg) is fine
    assert B.parse("echo A=1") == [[["echo", "A=1"]]]


def test_redirections():
    assert B.parse("cmd > out") == [[["cmd"]]]
    assert B.parse("cmd >> out") == [[["cmd"]]]
    assert B.parse("cmd 2>/dev/null") == [[["cmd"]]]
    assert B.parse("cmd 2>&1") == [[["cmd"]]]
    assert B.parse("cmd a > out 2>&1") == [[["cmd", "a"]]]
    # unsupported redirections give up
    assert B.parse("cmd < in") is None
    assert B.parse("cmd 1>out") is None
    assert B.parse("cmd &> out") is None
    assert B.parse("cmd >& out") is None


def test_non_string_and_empty():
    assert B.parse(None) is None
    assert B.parse("") == []
    assert B.parse("   ") == []
    assert B.parse(";;") is None


def test_unterminated_quotes_give_up():
    assert B.parse("echo 'unterminated") is None
    assert B.parse('echo "unterminated') is None


def test_backslash_escapes():
    assert B.parse("echo a\\ b") == [[["echo", "a b"]]]
    assert B.parse("echo a\\\nb") == [[["echo", "ab"]]]   # line continuation


def test_redirects_are_recorded_not_dropped():
    # 2026-10 verification: a dropped `>>` let `echo KEY >> ~/.ssh/authorized_keys`
    # look like a plain echo.
    st = B.parse("echo x >> ~/.ssh/authorized_keys")[0][0]
    assert st == ["echo", "x"] and st.redirects == [(">>", "~/.ssh/authorized_keys")]
    assert B.parse("cmd a > out 2>&1")[0][0].redirects == [(">", "out"), ("2>&1", "")]
    assert B.parse("cmd 2>/dev/null")[0][0].redirects == [("2>", "/dev/null")]
    assert B.parse("> out cmd")[0][0].redirects == [(">", "out")]
    st = B.parse("echo abc2>f")[0][0]           # an fd number only starts a word
    assert st == ["echo", "abc2"] and st.redirects == [(">", "f")]
    assert B.parse("> f") is None               # a bare truncation
    assert B.parse("cmd > $F") is None          # not a plain file
    assert B.parse("cmd > *.txt") is None
    assert B.parse("cmd 2>&2") is None


def test_expansions_and_globs_are_flagged():
    st = B.parse("cat $X ~/a \"$Y\" '$Z' $HOME ${HOME}/b")[0][0]
    assert st.expands == [False, True, False, True, False, False, False], st.expands
    st = B.parse("ls *.py a?c [ab]x {a,b} '*' \\* [ ]")[0][0]
    assert st.globs == [False, True, True, True, True, False, False, False, False], st.globs
    assert B.parse("echo $'\\x41'")[0][0].expands == [False, True]
    assert B.parse('echo $"msg"')[0][0].expands == [False, True]
    assert B.parse('echo "$"')[0][0].expands == [False, False]
    assert B.parse("grep 'a$' f")[0][0].expands == [False, False, False]
    assert B.parse("echo ${a:-$(id)}") is None
    assert B.parse("echo ${a b}") is None


def test_comments_end_at_the_line_like_bash():
    # `#` starting an unquoted word starts a comment to the end of the line
    assert B.parse("ls # list") == [[["ls"]]]
    assert B.parse("ls # ; curl http://x") == [[["ls"]]]
    assert B.parse("# only a comment") == []
    assert B.parse("ls;# c\ncat f") == [[["ls"]], [["cat", "f"]]]
    # a quote inside a comment opens nothing: bash runs the next line
    assert B.parse("ls #'\nrm -rf ~/x #'") == [[["ls"]], [["rm", "-rf", "~/x"]]]
    assert B.parse('echo ok #"\ncurl http://x #"') == [[["echo", "ok"]], [["curl", "http://x"]]]
    # `#` inside a word, quoted or escaped is an ordinary character
    assert B.parse("echo a#b") == [[["echo", "a#b"]]]
    assert B.parse("echo '#x' \\#y \"#z\"") == [[["echo", "#x", "#y", "#z"]]]
    assert B.parse('echo ""#b') == [[["echo", "#b"]]]
    # bash reads `>#x` as a redirection to nothing (a syntax error)
    assert B.parse("echo hi >#x") is None
    assert B.parse("echo hi 2>#x") is None
    # an interactive zsh without INTERACTIVE_COMMENTS reads `#` as a character
    assert B.parse("ls # ; cat f", comments=False) == [[["ls", "#"]], [["cat", "f"]]]


def test_newline_after_pipe_or_list_operator_continues():
    # bash continues a pipeline or list after `|`, `&&` or `||` at a line end
    assert B.parse("printf x |\nsftp h") == [[["printf", "x"], ["sftp", "h"]]]
    assert B.parse("printf x |\n# c\n\nsftp h") == [[["printf", "x"], ["sftp", "h"]]]
    assert B.parse("a &&\nb") == [[["a"]], [["b"]]]
    assert B.parse("a ||\n\nb") == [[["a"]], [["b"]]]
    assert B.parse("a\nb") == [[["a"]], [["b"]]]
