"""
Tests for the auth log analyzer.

Run with:  python3 -m unittest

A tiny fake log is written to a temporary file so the test doesn't depend on the
sample data file and cleans up after itself.
"""

import os
import tempfile
import unittest

from analyze import analyze


SAMPLE_LOG = """\
Jun 15 06:01:11 server sshd[1]: Accepted password for liv from 192.168.1.20 port 1 ssh2
Jun 15 06:14:02 server sshd[2]: Failed password for root from 203.0.113.55 port 2 ssh2
Jun 15 06:14:04 server sshd[2]: Failed password for admin from 203.0.113.55 port 3 ssh2
Jun 15 06:14:06 server sshd[2]: Failed password for test from 203.0.113.55 port 4 ssh2
Jun 15 06:14:08 server sshd[2]: Failed password for oracle from 203.0.113.55 port 5 ssh2
Jun 15 06:14:10 server sshd[2]: Failed password for git from 203.0.113.55 port 6 ssh2
Jun 15 07:00:00 server sshd[3]: Failed password for liv from 198.51.100.7 port 7 ssh2
"""


class TestAnalyze(unittest.TestCase):
    def setUp(self):
        # Write the fake log to a temp file.
        self.tmp = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
        self.tmp.write(SAMPLE_LOG)
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_counts_failures_per_ip(self):
        failures, _, _, _ = analyze(self.tmp.name, threshold=5)
        self.assertEqual(failures["203.0.113.55"], 5)
        self.assertEqual(failures["198.51.100.7"], 1)

    def test_flags_ip_over_threshold(self):
        _, _, _, suspicious = analyze(self.tmp.name, threshold=5)
        self.assertIn("203.0.113.55", suspicious)
        self.assertNotIn("198.51.100.7", suspicious)

    def test_threshold_is_respected(self):
        # With a stricter threshold, the single-failure IP still isn't flagged.
        _, _, _, suspicious = analyze(self.tmp.name, threshold=2)
        self.assertIn("203.0.113.55", suspicious)
        self.assertNotIn("198.51.100.7", suspicious)

    def test_tracks_usernames_tried(self):
        _, failed_users, _, _ = analyze(self.tmp.name, threshold=5)
        self.assertIn("root", failed_users["203.0.113.55"])
        self.assertIn("oracle", failed_users["203.0.113.55"])


if __name__ == "__main__":
    unittest.main()
