from __future__ import annotations

import unittest

from fixinspector.fix.framing import FixFramer

from tests.support import fix_message


class FixFramerCharacterizationTests(unittest.TestCase):
    def test_reassembles_a_message_fed_one_byte_at_a_time(self) -> None:
        raw = fix_message(extra_fields=[("11", b"ORDER-1")])
        framer = FixFramer()
        framed: list[bytes] = []

        for byte in raw:
            framed.extend(framer.feed(bytes([byte])))

        self.assertEqual([raw], framed)
        self.assertEqual(b"", framer.buffer)

    def test_reassembles_across_every_two_chunk_split(self) -> None:
        raw = fix_message(extra_fields=[("11", b"ORDER-2")])

        for split_at in range(len(raw) + 1):
            with self.subTest(split_at=split_at):
                framer = FixFramer()
                first = framer.feed(raw[:split_at])
                second = framer.feed(raw[split_at:])
                self.assertEqual([raw], first + second)
                self.assertEqual(b"", framer.buffer)

    def test_extracts_multiple_coalesced_messages(self) -> None:
        first = fix_message(seq_num=10, extra_fields=[("11", b"A")])
        second = fix_message(seq_num=11, extra_fields=[("11", b"B")])

        framer = FixFramer()

        self.assertEqual([first, second], framer.feed(first + second))
        self.assertEqual(b"", framer.buffer)

    def test_body_length_allows_soh_inside_the_body(self) -> None:
        raw = fix_message(extra_fields=[("95", b"3"), ("96", b"A\x01B")])

        self.assertEqual([raw], FixFramer().feed(raw))

    def test_malformed_body_length_is_retained_and_stream_resynchronizes(self) -> None:
        raw = fix_message(seq_num=20, extra_fields=[("11", b"ORDER")])
        following = fix_message(seq_num=21, extra_fields=[("11", b"FOLLOWING")])
        tag9_start = raw.find(b"9=")
        tag9_end = raw.find(b"\x01", tag9_start)
        malformed = raw[:tag9_start] + b"9=999" + raw[tag9_end:]
        framer = FixFramer()

        frames = framer.feed_frames(malformed + following)

        self.assertEqual([malformed, following], [frame.raw for frame in frames])
        self.assertIn("BodyLength", frames[0].error)
        self.assertIsNone(frames[1].error)
        self.assertEqual(b"", framer.buffer)

    def test_flush_exposes_truncated_final_frame(self) -> None:
        raw = fix_message(extra_fields=[("11", b"TRUNCATED")])
        framer = FixFramer()

        self.assertEqual([], framer.feed(raw[:-4]))
        flushed = framer.flush()

        self.assertEqual(raw[:-4], flushed[0].raw)
        self.assertIn("incomplete", flushed[0].error)
        self.assertEqual(b"", framer.buffer)


if __name__ == "__main__":
    unittest.main()
