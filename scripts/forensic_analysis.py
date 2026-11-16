#!/usr/bin/env python3
"""Forensic timeline reconstruction for the web01 incident.

Reads three evidence sources (bash history, auth log excerpt, suspicious
file list) plus the recovered crontab, normalizes every timestamp to UTC,
classifies each event (noise vs. malicious), and emits timeline.json plus
a human-readable summary on stdout.

Usage:
    python -I forensic_analysis.py <evidence_dir> <timeline_json_out>

Clock model (documented assumptions, see summary section 5):
  - bash_history.txt  : epoch seconds (HISTTIMEFORMAT), unambiguous -> UTC.
  - auth_excerpt.log  : syslog "Mon DD HH:MM:SS", no year/tz. Year inferred
                        as 2026 from files.txt; assumed host-local == UTC.
  - files.txt         : "YYYY-MM-DD HH:MM" mtimes, assumed host-local == UTC.
  Cross-source check: files.txt mtimes are ~36 min EARLIER than the
  bash_history commands that created those files, so mtime-based ordering
  is treated as low-confidence (skew or timestomping).
"""

import json
import re
import sys
from datetime import datetime, timezone

NOISE_COMMANDS = {
    "cd /var/log",
    "tail -f app.log",
    "git pull",
    "ls -la",
    "systemctl status nginx",
}

MONTHS = {"Oct": 10}


def iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_bash_history(path):
    """Yield (line_no_of_command, epoch, command)."""
    events = []
    pending_ts = None
    pending_line = None
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.rstrip("\n")
            if line.startswith("#") and line[1:].isdigit():
                pending_ts = int(line[1:])
                pending_line = lineno
            elif line.strip() and pending_ts is not None:
                events.append((lineno, pending_line, pending_ts, line.strip()))
                pending_ts = None
    return events


def parse_auth_log(path):
    """Yield (lineno, kind, dt_or_none, text)."""
    events = []
    rx = re.compile(r"^(\w{3})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})\s+\S+\s+(.*)$")
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.rstrip("\n")
            m = rx.match(line)
            if not m:
                continue
            mon, day, hh, mm, ss, rest = m.groups()
            dt = datetime(2026, MONTHS[mon], int(day), int(hh), int(mm), int(ss),
                          tzinfo=timezone.utc)
            kind = "sshd" if rest.startswith("sshd") else "web"
            events.append((lineno, kind, dt, rest))
    return events


def parse_files(path):
    events = []
    rx = re.compile(r"^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})\s+(\d+)\s+(\S+)\s+(\S.*)$")
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            m = rx.match(raw.strip())
            if m:
                d, t, perm, owner, fpath = m.groups()
                dt = datetime.fromisoformat(f"{d}T{t}:00").replace(tzinfo=timezone.utc)
                events.append((lineno, dt, perm, owner, fpath.strip()))
    return events


def classify_bash(cmd):
    if cmd in NOISE_COMMANDS:
        return "noise", "routine ops command (log tailing / git pull / service status)"
    if cmd.startswith("php -r") and "shell.php" in cmd:
        return "malicious", "writes PHP webshell (system($_GET[cmd])) into uploads dir"
    if cmd == "crontab -e":
        return "malicious", "edits crontab -> persistence (see crontab.txt:3)"
    if cmd.startswith("cd /var/www/html/uploads"):
        return "suspicious", "moves into web-uploads dir immediately before webshell write"
    return "suspicious", "unrecognized command"


def main(evidence_dir, out_path):
    timeline = []

    # --- 1. bash history (epoch -> UTC, authoritative clock) ---
    for lineno, ts_line, epoch, cmd in parse_bash_history(f"{evidence_dir}/bash_history.txt"):
        sev, note = classify_bash(cmd)
        timeline.append({
            "time_utc": iso(datetime.fromtimestamp(epoch, timezone.utc)),
            "source": f"evidence/bash_history.txt:{lineno}",
            "type": "shell_command",
            "event": cmd,
            "classification": sev,
            "note": note,
            "clock": "epoch (exact)",
        })

    # --- 2. auth log ---
    for lineno, kind, dt, rest in parse_auth_log(f"{evidence_dir}/auth_excerpt.log"):
        if kind == "sshd":
            sev, note = "noise", "ops user, publickey auth from internal 10.20.1.0/24 - routine"
        elif "POST /upload.php" in rest:
            sev, note = "malicious", "ENTRY VECTOR: file upload endpoint used to plant shell.php"
        elif "shell.php" in rest and "cmd=" in rest:
            sev, note = "malicious", "webshell executed remotely (?cmd=id)"
        else:
            sev, note = "suspicious", "web request"
        timeline.append({
            "time_utc": iso(dt),
            "source": f"evidence/auth_excerpt.log:{lineno}",
            "type": "auth_log" if kind == "sshd" else "web_access",
            "event": rest,
            "classification": sev,
            "note": note,
            "clock": "syslog, year/tz assumed (2026, host-local==UTC)",
        })

    # --- 3. suspicious file list (mtimes) ---
    for lineno, dt, perm, owner, fpath in parse_files(f"{evidence_dir}/files.txt"):
        if fpath.endswith("shell.php"):
            sev, note = "malicious", "webshell on disk, owned by www-data (web-server context)"
        elif "crontab" in fpath:
            sev, note = "malicious", "www-data crontab modified -> persistence (crontab.txt:3)"
        else:
            sev, note = "info", "mtime changed but no corroborating evidence; not flagged"
        timeline.append({
            "time_utc": iso(dt),
            "source": f"evidence/files.txt:{lineno}",
            "type": "file_mtime",
            "event": f"{fpath} (perm {perm}, owner {owner})",
            "classification": sev,
            "note": note,
            "clock": "file mtime, host-local==UTC assumed; LOW confidence (skew/timestomp suspected)",
        })

    timeline.sort(key=lambda e: (e["time_utc"], e["source"]))

    doc = {
        "incident": "web01 suspected compromise, 2026-10-01 early morning (UTC)",
        "clock_alignment": {
            "bash_history.txt": "epoch seconds -> UTC (exact)",
            "auth_excerpt.log": "syslog timestamps; year 2026 inferred from files.txt; tz assumed UTC",
            "files.txt": "mtimes assumed host-local==UTC; inconsistent with bash_history "
                         "(mtimes ~36 min earlier than the commands that created the files) "
                         "-> treated as low confidence",
        },
        "events": timeline,
        "conclusions": {
            "entry_vector": {
                "finding": "web shell upload via POST /upload.php, shell executed via "
                           "GET /uploads/shell.php?cmd=id; shell written from www-data context",
                "evidence": [
                    "evidence/auth_excerpt.log:27",
                    "evidence/auth_excerpt.log:26",
                    "evidence/bash_history.txt:54",
                    "evidence/files.txt:2",
                ],
            },
            "persistence": {
                "finding": "cron job under www-data pulling and executing a remote script "
                           "every 5 minutes (curl | bash from 203.0.113.66)",
                "evidence": [
                    "evidence/crontab.txt:3",
                    "evidence/bash_history.txt:56",
                    "evidence/files.txt:3",
                ],
            },
            "noise_not_flagged": [
                "evidence/auth_excerpt.log:1-25 (ops SSH logins, internal subnet, publickey)",
                "evidence/bash_history.txt routine commands: cd /var/log, tail -f app.log, "
                "git pull, ls -la, systemctl status nginx",
                "evidence/files.txt:1 (/etc/passwd mtime change, no corroboration)",
            ],
        },
    }

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)

    # --- summary to stdout ---
    print("=== TIMELINE (UTC, noise collapsed) ===")
    for e in timeline:
        if e["classification"] != "noise":
            print(f"{e['time_utc']}  [{e['classification']:9s}]  {e['source']:38s}  {e['event']}")
    n_noise = sum(1 for e in timeline if e["classification"] == "noise")
    print(f"... plus {n_noise} noise events (routine ops, not anomalies)")
    print("\n=== CONCLUSIONS ===")
    print("Entry vector : web shell upload "
          "(auth_excerpt.log:27, auth_excerpt.log:26, bash_history.txt:54, files.txt:2)")
    print("Persistence  : cron, www-data, curl|bash every 5 min "
          "(crontab.txt:3, bash_history.txt:56, files.txt:3)")
    print("Account      : www-data (web-server context), NOT the ops SSH account")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "evidence",
         sys.argv[2] if len(sys.argv) > 2 else "timeline.json")
