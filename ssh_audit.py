"""Shared CLI and SSH transport for read-only host audits."""

import glob
import re
import shlex
import subprocess
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

Rows = list[tuple[str, str]]


def config_hosts(path: Path, stack: tuple[Path, ...] = ()) -> list[str]:
    """Enumerate literal aliases; let OpenSSH resolve connection options."""
    path = path.resolve()
    if path in stack:
        raise ValueError(f"recursive SSH Include: {path}")
    hosts = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        parts = re.split(r"\s*=\s*|\s+", line.strip(), maxsplit=1)
        if len(parts) != 2 or parts[0].lower() not in {"host", "include"}:
            continue
        key, value = parts
        try:
            values = shlex.split(value, comments=True)
        except ValueError as exc:
            raise ValueError(f"{path}:{number}: {exc}") from exc
        if key.lower() == "host":
            hosts.extend(h for h in values if not any(c in h for c in "*?!"))
            continue
        for pattern in values:
            expanded = Path(pattern).expanduser()
            if not expanded.is_absolute():
                expanded = Path.home() / ".ssh" / expanded
            for included in sorted(glob.glob(str(expanded))):
                hosts.extend(config_hosts(Path(included), (*stack, path)))
    return list(dict.fromkeys(hosts))


def _run_ssh(host: str, remote: str, probe: str) -> tuple[str, str, str]:
    """Return probe output, transport failure (if any), and stderr."""
    options = (
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "ConnectTimeout=5",
        "ConnectionAttempts=1",
        "ServerAliveInterval=5",
        "ServerAliveCountMax=2",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "RemoteCommand=none",
        "RequestTTY=no",
    )
    command = ["ssh", "-T", *("-o" + option for option in options), "--", host, remote]
    try:
        result = subprocess.run(command, input=probe, capture_output=True, text=True, errors="replace", timeout=30)
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"").decode(errors="replace")
        return output, "SSH/probe timed out after 30s", (exc.stderr or b"").decode(errors="replace").strip()
    failure = f"SSH/probe exit {result.returncode}" if result.returncode else ""
    return result.stdout, failure, result.stderr.strip()


def _print_tsv(host: str, rows: Rows) -> None:
    for status, detail in rows:
        print(f"{host}\t{status}\t{detail}", flush=True)


def _plain_report(host: str, rows: Rows, diagnostic: str) -> None:
    _print_tsv(host, rows)
    if diagnostic:
        print(f"{host}: {diagnostic}", file=sys.stderr)


def _rich_reporter(styles: dict[str, str]) -> Callable[[str, Rows, str], None]:
    from rich.console import Console
    from rich.padding import Padding
    from rich.text import Text

    terminal = sys.stdout.isatty()
    out = Console()
    err = Console(stderr=True)

    def report(host: str, rows: Rows, diagnostic: str) -> None:
        if terminal:
            out.print(Text(host, style="bold"))
            for status, detail in rows:
                line = Text.assemble((status, styles[status]), "  ", detail)
                out.print(Padding(line, (0, 0, 0, 2), expand=False))
        else:
            _print_tsv(host, rows)
        if diagnostic:
            err.print(Text(f"  {host} stderr:", style="dim"), soft_wrap=True)
            if sys.stderr.isatty():
                err.print(Padding(Text(diagnostic), (0, 0, 0, 4), expand=False))
            else:
                for line in diagnostic.splitlines():
                    print(f"    {line}", file=sys.stderr)
        if terminal:
            out.print()

    return report


def run_check(
    *,
    help_text: str,
    probe: str,
    findings: Callable[[str, str], Rows],
    ok_statuses: set[str],
    remote: str = "sh -s",
    styles: dict[str, str] | None = None,
) -> int:
    """Run a probe per host. Each parser returns at least one (status, detail) row."""
    args = sys.argv[1:]
    if args in (["--help"], ["-h"]):
        print(help_text)
        return 0
    if args and args[0] in {"--sudo", "--doas"}:
        elevation = args.pop(0)[2:]
        remote = f'if [ "$(id -u)" -eq 0 ]; then {remote}; else {elevation} -n {remote}; fi'

    def severity(status: str) -> int:
        if status == "AT_RISK":
            return 2
        return 0 if status in ok_statuses else 1

    try:
        list_only = args == ["--list"]
        hosts = config_hosts(Path.home() / ".ssh/config") if list_only or not args else list(dict.fromkeys(args))
        if not hosts:
            raise ValueError("no literal SSH Host aliases found")
        if any(not host.strip() or host.startswith("-") for host in hosts):
            raise ValueError("invalid host/option; see --help")
        if list_only:
            print("\n".join(hosts))
            return 0
        report = _plain_report if styles is None else _rich_reporter(styles)
        if styles is None or not sys.stdout.isatty():
            print("SSH_ALIAS\tSTATUS\tDETAILS", flush=True)
        counts: dict[str, int] = {}
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {pool.submit(_run_ssh, host, remote, probe): host for host in hosts}
            for future in as_completed(futures):
                host = futures[future]
                output, failure, diagnostic = future.result()
                rows = findings(output, failure)
                worst = max((status for status, _ in rows), key=severity)
                counts[worst] = counts.get(worst, 0) + 1
                report(host, rows, diagnostic)
        summary = "; ".join(f"{status}={n}" for status, n in sorted(counts.items()))
        print(f"Scanned: {len(hosts)}; {summary}", file=sys.stderr)
        return max(map(severity, counts))
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
