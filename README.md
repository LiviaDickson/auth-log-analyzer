# Auth Log Analyzer

A command-line tool that reads an SSH authentication log and spots likely
**brute-force attacks** — one IP address trying to guess its way in by failing
to log in over and over.

## The problem it solves

A brute-force attack is when an attacker tries thousands of username/password
combinations hoping one works. In a log file it shows up as a single IP address
piling up `Failed password` lines. A human scrolling the log will never catch it,
but counting failures per IP makes it jump out instantly.

This is the same core idea behind real defensive tools like
[fail2ban](https://github.com/fail2ban/fail2ban), built small enough to read and
understand.

## What it does

- Reads each line of the log once
- Counts failed and successful logins per IP address
- Flags any IP that fails more times than the alert threshold
- Lists which usernames each suspicious IP tried (attackers spray common names
  like `root`, `admin`, `oracle`, `postgres`)
- Recommends an action

## Why I built it this way

- **Regular expressions to extract the IP and username.** Logs are messy text;
  a regex reliably pulls the two fields that matter out of each line without
  caring about the rest.
- **One pass through the file.** It reads the log line by line instead of loading
  the whole thing into memory, so it still works on a huge production log file,
  not just this small sample.
- **A configurable threshold.** What counts as "an attack" depends on the system,
  so the number of failures that triggers an alert is a flag you can change with
  `--threshold` rather than a fixed number buried in the code.
- **No external libraries** – runs on any machine with Python 3.

## How to run it

```bash
python3 analyze.py
```

Make it stricter or looser:

```bash
python3 analyze.py --threshold 3
```

Options:

| Flag | What it does | Default |
|------|--------------|---------|
| `--file` | path to the auth log | `data/auth.log` |
| `--threshold` | failures from one IP before it's flagged | `5` |

## Example output

```
Successful logins : 4
Failed attempts   : 15
Unique IPs failing: 4
Alert threshold   : 5 failures from one IP

POSSIBLE BRUTE-FORCE SOURCES (worst first)
  203.0.113.55     7 failed attempts
                   usernames tried: admin, oracle, root, test
  203.0.113.99     6 failed attempts
                   usernames tried: git, postgres, ubuntu
```

## The sample data

`data/auth.log` is a small, made-up SSH log containing normal logins plus two
simulated brute-force bursts. The IP ranges used (`203.0.113.x`, `198.51.100.x`,
`192.168.x.x`) are reserved for documentation and testing, so they're safe to
publish.

## Tests

Unit tests write a small fake log to a temporary file and confirm the failure
counts, the threshold behaviour, and the usernames tracked per IP. Run them with:

```bash
python3 -m unittest
```

## What I'd add next

- Detecting slow attacks spread out over hours to dodge the threshold
- Looking up whether a flagged IP later succeeded (a successful breach)
- Reading live logs and alerting in real time
