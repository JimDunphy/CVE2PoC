#!/bin/sh
# zimbra-cve.sh — see and track the CVEs affecting a Zimbra version.
#
#   ./zimbra-cve.sh install          install / set up the tool
#   ./zimbra-cve.sh update           reinstall/update the tool
#   ./zimbra-cve.sh show   10.1      show the full current CVE table (any time)
#   ./zimbra-cve.sh watch  10.1      monitor: baseline, then only what changed
#   ./zimbra-cve.sh cve    CVE-...   details + public PoCs for one CVE
#   ./zimbra-cve.sh help
#
# Valid Zimbra versions: train shortcuts (10.1, 10.0, 9.0, 8.8) or an exact
# version such as 10.1.16, 9.0.0.p46, or 8.8.15.p47. Extra args after a
# version/CVE are forwarded to cve2poc.

set -eu

# Where to install from. When this script sits inside a checkout (has a
# pyproject.toml next to it) we install from that checkout; otherwise from the
# public repo. Set REPO_URL when publishing.
REPO_URL="https://github.com/CHANGEME/CVE2PoC"
PYTHON_PIN="3.12"
UV_INSTALL_URL="https://astral.sh/uv/install.sh"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$SCRIPT_DIR/pyproject.toml" ]; then
    SRC="$SCRIPT_DIR"
else
    SRC="git+$REPO_URL"
fi

# Make sure uv's default tool-bin dir is visible so an already-installed
# cve2poc is found in later invocations (uv installs executables to ~/.local/bin).
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) PATH="$HOME/.local/bin:$PATH"; export PATH ;;
esac

usage() {
    cat <<EOF
zimbra-cve.sh — see and track Zimbra CVEs

Usage:
  $0 install            Install the tool (prompts before uv bootstrap; pins Python $PYTHON_PIN)
  $0 update             Reinstall/update the tool
  $0 show   <ver>       Show the full current CVE table for a Zimbra version
  $0 watch  <ver>       Monitor: baseline once, then only new/worsened CVEs (cron)
  $0 cve    <CVE-ID>    Details + public PoCs for a single CVE
  $0 help               This help

<ver> is either a train (10.1, 10.0, 9.0, 8.8) — resolved to that line's latest
patch — or an exact version (10.1.16, 9.0.0.p46, 8.8.15.p47).

Examples:
  $0 install
  $0 show 10.1          # latest 10.1 patch
  $0 show 10.1.16       # a specific patch level
  $0 watch 8.8 --state-file /srv/monitoring/zimbra88.json
  $0 cve CVE-2024-27443
EOF
}

need_tool() {
    if ! command -v cve2poc >/dev/null 2>&1; then
        echo "error: cve2poc is not installed. Run: $0 install" >&2
        exit 1
    fi
}

# Ensure uv is available, bootstrapping it if the user explicitly approves. uv
# is a single static binary and can supply its own Python, so this makes
# 'install' work on a bare box without relying on the system Python.
ensure_uv() {
    command -v uv >/dev/null 2>&1 && return 0
    for d in "$HOME/.local/bin" "$HOME/.cargo/bin"; do
        if [ -x "$d/uv" ]; then
            PATH="$d:$PATH"; export PATH; return 0
        fi
    done

    echo "[*] 'uv' was not found."
    echo
    echo "To install cve2poc safely, this script can bootstrap uv for you."
    echo "If you approve, it will:"
    echo "  1. download Astral's uv installer from:"
    echo "     $UV_INSTALL_URL"
    echo "  2. execute that installer with sh"
    echo "  3. add uv from ~/.local/bin or ~/.cargo/bin to PATH for this run"
    echo "  4. use uv to install cve2poc from:"
    echo "     $SRC"
    echo
    echo "No Zimbra host is contacted by this bootstrap step."
    echo "Prefer to install uv yourself? Answer no, install uv, then rerun:"
    echo "  $0 install"
    echo

    if [ ! -t 0 ]; then
        echo "error: refusing to bootstrap uv without terminal confirmation." >&2
        echo "       Install uv yourself, then rerun: $0 install" >&2
        exit 1
    fi
    printf "Install uv now? [y/N] "
    read answer
    case "$answer" in
        y|Y|yes|YES) ;;
        *)
            echo "Aborted. Install uv yourself, then rerun: $0 install" >&2
            exit 1
            ;;
    esac

    echo "[*] Installing uv from $UV_INSTALL_URL"
    if command -v curl >/dev/null 2>&1; then
        curl -LsSf "$UV_INSTALL_URL" | sh
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$UV_INSTALL_URL" | sh
    else
        echo "error: need 'curl' or 'wget' to install uv." >&2
        exit 1
    fi

    for d in "$HOME/.local/bin" "$HOME/.cargo/bin"; do
        [ -x "$d/uv" ] && { PATH="$d:$PATH"; export PATH; }
    done
    if ! command -v uv >/dev/null 2>&1; then
        echo "error: uv installation did not succeed." >&2
        exit 1
    fi
}

do_install() {
    ensure_uv
    # --python 3.12 makes uv fetch a managed interpreter if the box lacks one,
    # avoiding the older-system-Python crash.
    uv tool install --force --python "$PYTHON_PIN" "$SRC"
    uv tool update-shell >/dev/null 2>&1 || true
}

cmd_install() {
    do_install
    echo
    if command -v cve2poc >/dev/null 2>&1; then
        echo "Installed. cve2poc $(cve2poc --version 2>/dev/null | grep '^CVE2PoC ' | tail -1)"
        echo "Try:  $0 show 10.1"
    else
        echo "Installed, but cve2poc is not on PATH in this shell yet."
        echo "Open a new shell (or add ~/.local/bin to PATH), then:  $0 show 10.1"
    fi
}

cmd_update() {
    do_install
    echo "Updated to cve2poc $(cve2poc --version 2>/dev/null | grep '^CVE2PoC ' | tail -1)"
}

cmd_show() {
    [ $# -ge 1 ] || { echo "error: 'show' needs a version (e.g. 10.1 or 10.1.16)" >&2; exit 2; }
    ver="$1"; shift
    need_tool
    # Discover ALL Zimbra CVEs (keyword, Zimbra-independent) and sort by
    # relevance to this version — see everything, not just what NVD ties to a CPE.
    exec cve2poc --zimbra-scan "$ver" "$@"
}

cmd_watch() {
    [ $# -ge 1 ] || { echo "error: 'watch' needs a version (e.g. 10.1 or 10.1.16)" >&2; exit 2; }
    ver="$1"; shift
    need_tool
    cpe=$(cve2poc --zimbra-cpe "$ver") || exit $?
    exec cve2poc --watch "$cpe" "$@"
}

cmd_cve() {
    [ $# -ge 1 ] || { echo "error: 'cve' needs a CVE ID (e.g. CVE-2024-27443)" >&2; exit 2; }
    need_tool
    exec cve2poc "$@"
}

[ $# -eq 0 ] && { usage; exit 0; }

verb="$1"; shift
case "$verb" in
    install)      cmd_install "$@" ;;
    update)       cmd_update "$@" ;;
    show)         cmd_show "$@" ;;
    watch)        cmd_watch "$@" ;;
    cve)          cmd_cve "$@" ;;
    help | -h | --help) usage ;;
    *)
        echo "error: unknown command '$verb'" >&2
        usage
        exit 2
        ;;
esac
