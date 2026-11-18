#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["rich"]
# ///
"""Audit installed and running nginx binaries over SSH."""

import re
import sys

from ssh_audit import run_check

FIRST_AFFECTED = (1, 9, 5)
LAST_AFFECTED = (1, 31, 8)
STATUS_STYLE = {"AT_RISK": "bold red", "UNKNOWN": "yellow", "OUT_OF_RANGE": "green", "NOT_FOUND": "dim"}

PROBE = r"""
emit() { printf '\000nginx-audit\000%s\000%s\000%s\000' "$1" "$2" "$3"; }
my_uid=$(id -u) || exit 1
seen='
'
run_version() {
    # A worker owned by another account must not get the auditor's privileges.
    if [ "$2" = "$my_uid" ] || [ "$2" = 0 ]; then "$1" -v
    elif [ "$my_uid" != 0 ]; then echo "cannot run as uid $2" >&2; return 1
    elif command -v sudo >/dev/null; then sudo -n -u "#$2" -- "$1" -v
    elif command -v doas >/dev/null; then doas -n -u "$2" "$1" -v
    elif command -v su >/dev/null && entry=$(getent passwd "$2"); then
        su -s /bin/sh -c 'exec "$1" -v' "${entry%%:*}" sh "$1"
    elif command -v setpriv >/dev/null; then
        setpriv --reuid="$2" --regid="$3" --clear-groups --no-new-privs "$1" -v
    else echo "cannot drop privileges to uid $2" >&2; return 1; fi
}
check_binary() {
    label=$1 exe=$2 key=$3
    case "$seen" in *"
$key
"*) return ;; esac
    seen="$seen$key
"
    if version=$(run_version "$exe" "$4" "$5" 2>&1); then
        emit version "$label" "$version"
    else
        emit error "$label" "nginx -v failed (exit $?): $version"
    fi
}
check_path() {
    absolute=$(realpath "$1" 2>/dev/null) || absolute=$1
    case "$absolute" in /*) ;; *) absolute=$PWD/$absolute ;; esac
    check_binary "$absolute" "$absolute" "$absolute" "$2" "$3"
}

installed=$(command -v nginx) || installed=
for path in "$installed" /usr/sbin/nginx /usr/local/sbin/nginx /usr/local/nginx/sbin/nginx /opt/homebrew/bin/nginx; do
    [ -f "$path" ] && [ -x "$path" ] && check_path "$path" "$my_uid" ""
done

# Use process titles only for discovery; never execute a command parsed from argv.
if [ -d /proc/self ]; then
    for proc in /proc/[0-9]*; do
        IFS= read -r name 2>/dev/null < "$proc/comm" || continue
        if [ "$name" != nginx ]; then
            # A renamed binary still sets its title to "nginx: master process ...".
            # cmdline ends in NUL, not newline: read sets title but may return EOF.
            title=
            IFS= read -r title 2>/dev/null < "$proc/cmdline" || :
            case "$title" in 'nginx: '*) ;; *) continue ;; esac
        fi
        link=$proc/exe
        if ! path=$(readlink "$link"); then
            [ ! -d "$proc" ] || emit error "$link" "cannot read process executable (try --sudo/--doas)"
            continue
        fi
        ids=$(awk '/^Uid:/ {u=$3} /^Gid:/ {print u, $3; exit}' "$proc/status")
        if [ -z "$ids" ]; then emit error "$link" "cannot read process credentials"; continue; fi
        if [ "$path" -ef "$link" ]; then
            check_path "$path" "${ids% *}" "${ids#* }"
        elif inode=$(stat -Lc '%d:%i' "$link"); then
            # Deleted/replaced image or another mount namespace: the host
            # pathname may now be an entirely different version.
            check_binary "$path [$link]" "$link" "inode:$inode" "${ids% *}" "${ids#* }"
        else
            emit error "$path [$link]" "cannot identify running executable"
        fi
    done
elif processes=$(ps -Aww -o pid= -o uid= -o gid= -o comm=); then
    while read -r pid uid gid name; do
        case "$name" in
            /nginx|/*/nginx) check_path "$name" "$uid" "$gid" ;;
            nginx|nginx:*) emit error "pid $pid" "ps did not report an absolute nginx path" ;;
        esac
    done <<EOF
$processes
EOF
else
    emit error ps "cannot list processes"
fi
emit done "" ""
"""

HELP = """Usage: ssh_nginx.py [--sudo | --doas] [HOST ...]
       ssh_nginx.py --list

With no hosts, audit literal Host aliases from ~/.ssh/config and its Includes.
--list prints those aliases without connecting. --sudo/--doas are noninteractive.
Requires local Python 3.10+, rich and ssh (or use uv run ssh_nginx.py).
Redirected stdout stays TSV. SSH diagnostics and the summary go to stderr.

AT_RISK       nginx -v reports 1.9.5 through 1.31.8 inclusive.
OUT_OF_RANGE  Version is below 1.9.5 or above 1.31.8 (fix: 1.31.9).
NOT_FOUND     No nginx in PATH, standard fallback paths or the visible process list.
UNKNOWN       SSH/probe failed, or the version could not be identified.

Each distinct executable is checked with -v. Process paths come from /proc/PID/exe
on Linux or an absolute ps comm elsewhere. Vendor backports are not identified.
Results are per executable; the summary counts each host by its worst status.
Exit: 2 = any AT_RISK; 1 = errors/UNKNOWN; 0 = otherwise.
"""


def classify_version(value: str) -> tuple[str, str]:
    match = re.fullmatch(r"nginx version: nginx/([0-9]+\.[0-9]+\.[0-9]+)(?: \([^\r\n]*\))?", value)
    if not match:
        return "UNKNOWN", f"unexpected nginx -v output: {value!r}"
    version = tuple(map(int, match[1].split(".")))
    status = "AT_RISK" if FIRST_AFFECTED <= version <= LAST_AFFECTED else "OUT_OF_RANGE"
    return status, value.removeprefix("nginx version: ")


def findings(output: str, failure: str = "") -> list[tuple[str, str]]:
    rows = []
    done = False
    for kind, path, value in re.findall(r"\x00nginx-audit\x00([^\x00]+)\x00([^\x00]*)\x00([^\x00]*)\x00", output):
        if kind == "done":
            done = True
            continue
        status, detail = classify_version(value) if kind == "version" else ("UNKNOWN", value)
        rows.append((status, f"{path}: {detail}".replace("\t", " ").replace("\r", " ").replace("\n", " ")))
    if failure or not done:
        rows.append(("UNKNOWN", failure or "incomplete nginx probe response"))
    return rows or [("NOT_FOUND", "no installed or running nginx found")]


def main() -> int:
    return run_check(
        help_text=HELP,
        probe=PROBE,
        findings=findings,
        ok_statuses={"OUT_OF_RANGE", "NOT_FOUND"},
        styles=STATUS_STYLE,
    )


if __name__ == "__main__":
    sys.exit(main())
