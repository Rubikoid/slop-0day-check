#!/usr/bin/env python3
"""Read-only SSHhole prerequisite audit.

Sources: https://sshhole.com/
https://www.openssh.com/txt/release-10.6p2

No password attempts, remote files, configuration changes, or external uploads.
NOT_AFFECTED requires evidence from the serving process, not the OS name/banner.
Other results describe local accounts and DEFAULT ON-DISK sshd configuration for
the current connection's source address, not every possible Match context.
"""

import re
import sys

from ssh_audit import run_check

PROBE = r"""
set -f
emit() { printf '%s\t%s\n' "$1" "$2"; }
emit protocol sshhole-v1
emit system "$(uname -s)"
set -- ${1-}
peer=${1-}
local_addr=${3-}
local_port=${4-}

# Walk this connection's ancestors; do not inspect an unrelated sshd installation.
pid=$$
steps=0
libc=unknown
daemon=unknown
while [ "$pid" -gt 1 ] && [ "$steps" -lt 32 ]; do
    comm=$(cat "/proc/$pid/comm" 2>/dev/null) || break
    case "$comm" in
        dropbear*) daemon=dropbear; break ;;
        sshd*)
            daemon=openssh
            if [ -r "/proc/$pid/maps" ]; then
                libc=$(awk '
                    /\/ld-musl[^\/]*\.so|\/libc\.musl[^\/]*\.so/ {musl=1}
                    /\/libc\.so\.6|\/libc-[0-9][^\/]*\.so/ {glibc=1}
                    END {
                        if (musl && !glibc) print "musl"
                        else if (glibc && !musl) print "glibc"
                        else print "unknown"
                    }' "/proc/$pid/maps") || libc=unknown
            fi
            break ;;
    esac
    pid=$(awk '/^PPid:/ {print $2}' "/proc/$pid/status") || break
    case "$pid" in ''|*[!0-9]*) break ;; esac
    steps=$((steps + 1))
done
emit daemon "$daemon"
emit libc "$libc"
if [ "$daemon" = dropbear ] || [ "$libc" = glibc ]; then exit 0; fi

sshd=$(command -v sshd) || sshd=/usr/sbin/sshd
if [ ! -x "$sshd" ]; then emit error 'sshd binary not found'; exit 0; fi
version=$("$sshd" -V 2>&1) || version=unknown
emit installed_version "$version"
if [ ! -r /etc/shadow ]; then
    emit error '/etc/shadow unreadable; rerun as root or with --sudo/--doas'
    exit 0
fi
candidates=$(awk -F: '$2 == "*" {print $1}' /etc/shadow) || exit 1
real_hashes=$(awk -F: '$2 != "" && $2 !~ /^[!*]/ {n++} END {print n+0}' /etc/shadow) || exit 1
emit local_real_hashes "$real_hashes"
if [ -z "$candidates" ]; then emit local_star_accounts 0; exit 0; fi
if [ -z "$peer" ] || [ -z "$local_addr" ] || [ -z "$local_port" ]; then
    emit error 'SSH_CONNECTION unavailable; cannot evaluate Match context'
    exit 0
fi
count=0
enabled=0
errors=0
for user in $candidates; do
    count=$((count + 1))
    config=$("$sshd" -T -C "user=$user,addr=$peer,host=$peer,laddr=$local_addr,lport=$local_port")
    if [ "$?" -ne 0 ]; then
        emit config_error "$user: sshd -T failed"
        errors=$((errors + 1))
        continue
    fi
    password=$(printf '%s\n' "$config" | awk '$1 == "passwordauthentication" {print $2}')
    pam=$(printf '%s\n' "$config" | awk '$1 == "usepam" {print $2}')
    # A build without PAM may omit usepam entirely; absent is not 'yes'.
    if [ "$password" = no ] || [ "$pam" = yes ]; then continue; fi
    if [ "$password" != yes ]; then
        emit config_error "$user: PasswordAuthentication unavailable"
        errors=$((errors + 1))
        continue
    fi
    methods=$(printf '%s\n' "$config" | awk '$1 == "authenticationmethods" {$1=""; print $0}')
    if [ -z "$methods" ]; then
        emit config_error "$user: AuthenticationMethods unavailable"
        errors=$((errors + 1))
        continue
    fi
    # A password bypass alone cannot satisfy a publickey,password chain.
    case " $methods " in
        *" any "*|*" password "*) ;;
        *) continue ;;
    esac
    if [ "$user" = root ]; then
        root_login=$(printf '%s\n' "$config" | awk '$1 == "permitrootlogin" {print $2}')
        case "$root_login" in
            no|prohibit-password|without-password|forced-commands-only) continue ;;
            yes) ;;
            *) emit config_error 'root: PermitRootLogin unavailable'
               errors=$((errors + 1)); continue ;;
        esac
    fi
    enabled=$((enabled + 1))
    emit exposed_account "$user"
done
emit local_star_accounts "$count"
emit exposed_accounts "$enabled"
emit config_errors "$errors"
"""

HELP = """Usage: ssh_sshhole.py [--sudo | --doas] [HOST ...]
       ssh_sshhole.py --list

Default: audit literal Host aliases from ~/.ssh/config and recursive Includes.
Patterns (*, ?, !...) cannot be enumerated. Connection options, ProxyJump and
ProxyCommand are handled by OpenSSH. Python 3.10+ and ssh required; no pip deps.
--list: aliases only, no connections. --sudo/--doas: noninteractive elevation.
Existing keys/agent and known_hosts only; no password prompts or attack attempts.

NOT_AFFECTED: serving process is glibc OpenSSH or Dropbear.
AT_RISK: musl + local '*' accounts + other password hashes + password-only auth + no PAM.
PATCHED_ON_DISK: installed version >= 10.6p2; running version NOT verified.
MITIGATED_CONFIG: PAM/password mitigation in default on-disk config; reload NOT verified.
NO_LOCAL_CANDIDATES / NO_LOCAL_SALT: local shadow lacks a prerequisite; NSS NOT checked.
UNKNOWN: missing permissions, unsupported OS/daemon, or incomplete evidence.

Config checks cover local '*' accounts for this source IP only (host=source IP).
Custom sshd -f/-o flags, Match Host DNS rules, other sources and NSS can differ.
AT_RISK is a prerequisite finding, not a proven login; account/access rules can block it.
No result is a general SSH security assessment. No hashes leave the server.
Exit: 0 = all NOT_AFFECTED; 2 = any AT_RISK; 1 = remaining/incomplete results.
"""


def classify(output: str) -> tuple[str, str]:
    records: dict[str, list[str]] = {}
    for line in output.splitlines():
        if "\t" in line:
            key, value = line.split("\t", 1)
            records.setdefault(key, []).append(value)
    data = {key: values[-1] for key, values in records.items()}
    if data.get("protocol") != "sshhole-v1":
        return "UNKNOWN", "no probe response (remote command unavailable?)"
    if data.get("daemon") == "dropbear":
        return "NOT_AFFECTED", "serving process is Dropbear, not OpenSSH"
    if data.get("daemon") == "openssh" and data.get("libc") == "glibc":
        return "NOT_AFFECTED", "serving OpenSSH process uses glibc, not musl"
    details = f"libc={data.get('libc', 'unknown')}"
    version = data.get("installed_version", "unknown")
    match = re.search(r"OpenSSH_(\d+)\.(\d+)(?:p(\d+))?", version)
    if match:
        details += f"; installed={match.group(0)}"
    if data.get("error"):
        return "UNKNOWN", f"{details}; {'; '.join(records['error'])}"
    if data.get("daemon") != "openssh" or data.get("libc") != "musl":
        return "UNKNOWN", f"{details}; cannot identify serving daemon/libc (try --sudo)"
    if match and tuple(int(n or 0) for n in match.groups()) >= (10, 6, 2):
        return "PATCHED_ON_DISK", f"{details}; confirm running daemon was restarted"
    if not all(
        data.get(key, "").isdecimal()
        for key in ("local_star_accounts", "local_real_hashes")
    ):
        return "UNKNOWN", f"{details}; incomplete account evidence"
    if data.get("local_star_accounts") == "0":
        return (
            "NO_LOCAL_CANDIDATES",
            f"{details}; no local '*' accounts; NSS users not checked",
        )
    if data.get("local_real_hashes") == "0":
        return (
            "NO_LOCAL_SALT",
            f"{details}; no local real hashes; NSS users not checked",
        )
    accounts = records.get("exposed_account", [])
    if not all(
        data.get(key, "").isdecimal() for key in ("exposed_accounts", "config_errors")
    ) or int(data["exposed_accounts"]) != len(accounts):
        return "UNKNOWN", f"{details}; incomplete configuration evidence"
    if accounts:
        return (
            "AT_RISK",
            f"{details}; '*' accounts with passwords enabled and PAM off: {', '.join(accounts)}",
        )
    if data.get("config_errors") != "0" or data.get("exposed_accounts") != "0":
        errors = "; ".join(records.get("config_error", ["incomplete probe response"]))
        return "UNKNOWN", f"{details}; {errors}"
    return (
        "MITIGATED_CONFIG",
        f"{details}; local '*' accounts blocked by PAM/authentication/root settings; confirm reload",
    )


def findings(output: str, failure: str) -> list[tuple[str, str]]:
    return [("UNKNOWN", failure) if failure else classify(output)]


def main() -> int:
    return run_check(
        help_text=HELP,
        probe=PROBE,
        findings=findings,
        ok_statuses={"NOT_AFFECTED"},
        # Preserve the original connection tuple across sudo's environment reset.
        remote='sh -s -- "$SSH_CONNECTION"',
    )


if __name__ == "__main__":
    sys.exit(main())
