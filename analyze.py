#!/usr/bin/env python3
"""
Auth Log Analyzer
-----------------
Reads an SSH-style authentication log and spots likely brute-force attacks:
single IP addresses that failed to log in many times in a row.

Why this matters:
A brute-force attack is when someone tries thousands of username/password
combinations hoping one works. In the logs it looks like one IP address racking
up a pile of "Failed password" lines. A human scrolling a log won't catch it,
but counting failures per IP makes it obvious. This is the core idea behind
tools like fail2ban.

Runs with plain Python 3 - no libraries to install.
"""

import re
import argparse
from collections import defaultdict

# These patterns pull the IP address out of each log line.
FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
ACCEPTED = re.compile(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)")


def analyze(log_path, threshold):
    """
    Walk the log once and tally failures and successes per IP.
    Returns the counts plus the list of IPs that crossed the alert threshold.
    """
    failures = defaultdict(int)
    failed_users = defaultdict(set)
    successes = defaultdict(int)

    with open(log_path, encoding="utf-8") as f:
        for line in f:
            m = FAILED.search(line)
            if m:
                user, ip = m.group(1), m.group(2)
                failures[ip] += 1
                failed_users[ip].add(user)
                continue
            m = ACCEPTED.search(line)
            if m:
                successes[m.group(2)] += 1

    suspicious = {ip: n for ip, n in failures.items() if n >= threshold}
    return failures, failed_users, successes, suspicious


def main():
    parser = argparse.ArgumentParser(description="Find brute-force attempts in an auth log.")
    parser.add_argument("--file", default="data/auth.log", help="path to the auth log")
    parser.add_argument("--threshold", type=int, default=5,
                        help="failed attempts from one IP before it's flagged")
    args = parser.parse_args()

    failures, failed_users, successes, suspicious = analyze(args.file, args.threshold)

    total_failed = sum(failures.values())
    total_ok = sum(successes.values())

    print(f"\nSuccessful logins : {total_ok}")
    print(f"Failed attempts   : {total_failed}")
    print(f"Unique IPs failing: {len(failures)}")
    print(f"Alert threshold   : {args.threshold} failures from one IP\n")

    if suspicious:
        print("POSSIBLE BRUTE-FORCE SOURCES (worst first)")
        print("-" * 60)
        for ip, n in sorted(suspicious.items(), key=lambda x: x[1], reverse=True):
            users = ", ".join(sorted(failed_users[ip]))
            print(f"  {ip:16} {n} failed attempts")
            print(f"                   usernames tried: {users}")
        print("\nRecommended action: block these IPs at the firewall and review"
              "\nwhether any of the targeted accounts were later accessed.")
    else:
        print("No IPs crossed the alert threshold.")
    print()


if __name__ == "__main__":
    main()
