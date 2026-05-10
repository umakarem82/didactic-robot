import types
import unittest
from unittest import mock

import net_watch_plus


class NetWatchPlusParserTests(unittest.TestCase):
    def test_collect_via_ss_uses_peer_address_column(self) -> None:
        ss_output = (
            'tcp ESTAB 0 0 192.168.1.2:52000 '
            '203.0.113.10:3389 users:(("python3",pid=42,fd=7))\n'
        )

        with mock.patch(
            "net_watch_plus.subprocess.run",
            return_value=types.SimpleNamespace(stdout=ss_output),
        ):
            conns = net_watch_plus._collect_via_ss()

        self.assertEqual(len(conns), 1)
        conn = conns[0]
        self.assertEqual(conn.local, "192.168.1.2:52000")
        self.assertEqual(conn.remote, "203.0.113.10:3389")
        self.assertEqual(conn.pid, 42)
        self.assertEqual(conn.proc, "python3")
        self.assertIn("rdp", net_watch_plus.classify_basic(conn))

    def test_unspecified_remote_detection_handles_wildcards(self) -> None:
        self.assertIn(
            "unspecified-remote",
            net_watch_plus.classify_basic(
                net_watch_plus.Conn("udp", "127.0.0.1:1", "*:*", "UNCONN")
            ),
        )


if __name__ == "__main__":
    unittest.main()
