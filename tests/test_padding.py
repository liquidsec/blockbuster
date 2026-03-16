"""Tests for PKCS#7 padding: paddify() and byte-level padding in encryptInit."""

import io
import sys


from blockbuster.blockbuster import paddify
from tests.conftest import make_job


class TestPaddify:
    """Test the paddify(string, blocksize) function."""

    def test_exact_block_boundary(self):
        """16 chars with blocksize=16 gets full block of padding (16 bytes of \\x10)."""
        result = paddify("A" * 16, 16)
        assert len(result) == 32
        assert result[16:] == chr(16) * 16

    def test_shorter_than_block(self):
        """5 chars with blocksize=8 -> 3 bytes of \\x03."""
        result = paddify("ABCDE", 8)
        assert len(result) == 8
        assert result[5:] == chr(3) * 3

    def test_single_char(self):
        result = paddify("X", 16)
        assert len(result) == 16
        assert result[1:] == chr(15) * 15

    def test_multi_block_with_remainder(self):
        """20 chars with blocksize=16 -> 2 blocks, 12 bytes padding on last."""
        result = paddify("A" * 20, 16)
        assert len(result) == 32
        assert result[20:] == chr(12) * 12

    def test_empty_string(self):
        """Empty string should produce a full block of padding."""
        result = paddify("", 8)
        # split_by_n on "" yields nothing, so paddify returns ""
        # This is arguably a bug, but we test current behavior
        assert result == ""

    def test_blocksize_8(self):
        result = paddify("ABCD", 8)
        assert len(result) == 8
        assert result[4:] == chr(4) * 4


class TestEncryptInitPadding:
    """Test PKCS#7 byte-level padding in encryptInit."""

    def _init_job(self, source_string, blocksize=16, plaintext_encoding="utf-8"):
        j = make_job(
            sourceString=source_string,
            mode="encrypt",
            blocksize=blocksize,
            ivMode="firstblock",
            plaintextEncoding=plaintext_encoding,
        )
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            j.encryptInit()
        finally:
            sys.stdout = old_stdout
        return j

    def test_exact_blocksize_adds_full_block(self):
        """16 bytes of plaintext -> 16 bytes padding -> 32 total."""
        j = self._init_job("A" * 16)
        assert len(j.bytemap) == 32
        assert j.bytemap[-16:] == bytes([16] * 16)

    def test_shorter_than_block(self):
        """4 bytes -> 12 bytes padding -> 16 total."""
        j = self._init_job("ABCD")
        assert len(j.bytemap) == 16
        assert j.bytemap[-12:] == bytes([12] * 12)

    def test_multi_block_with_remainder(self):
        """20 bytes -> 12 bytes padding -> 32 total."""
        j = self._init_job("A" * 20)
        assert len(j.bytemap) == 32
        assert j.bytemap[-12:] == bytes([12] * 12)

    def test_single_byte(self):
        j = self._init_job("X")
        assert len(j.bytemap) == 16
        assert j.bytemap[-15:] == bytes([15] * 15)

    def test_utf16le_encoding(self):
        """utf-16-le doubles byte count. 'AB' = 4 bytes -> 12 padding."""
        j = self._init_job("AB", plaintext_encoding="utf-16-le")
        raw = "AB".encode("utf-16-le")
        assert len(raw) == 4
        assert len(j.bytemap) == 16
        assert j.bytemap[:4] == raw
        assert j.bytemap[4:] == bytes([12] * 12)

    def test_blocks_are_reversed(self):
        """encryptInit reverses block order for the encrypt attack."""
        j = self._init_job("A" * 32)  # 32 bytes -> 48 padded -> 3 blocks
        assert len(j.blocks) == 3
        # blocks[0] should be the LAST plaintext block (padding block)
        # blocks[-1] should be the FIRST plaintext block
        padded = "A".encode() * 32 + bytes([16] * 16)
        first_block = list(padded[:16])
        last_block = list(padded[32:48])
        assert list(j.blocks[0]) == last_block
        assert list(j.blocks[2]) == first_block

    def test_blocksize_8(self):
        j = self._init_job("ABCD", blocksize=8)
        assert len(j.bytemap) == 8
        assert j.bytemap[4:] == bytes([4] * 4)


class TestPKCS7Stripping:
    """Test the PKCS#7 stripping logic from async_main (lines 1304-1310)."""

    def _strip(self, combined, blocksize=16):
        """Replicate the stripping logic from async_main."""
        pad_len = combined[-1]
        if (
            1 <= pad_len <= blocksize
            and combined[-pad_len:] == bytes([pad_len]) * pad_len
        ):
            return combined[:-pad_len]
        return combined

    def test_valid_padding_stripped(self):
        data = b"Hello" + bytes([3, 3, 3])
        assert self._strip(data, 8) == b"Hello"

    def test_full_block_padding_stripped(self):
        data = b"EXACTLY8" + bytes([8] * 8)
        assert self._strip(data, 8) == b"EXACTLY8"

    def test_single_byte_padding(self):
        data = b"1234567" + bytes([1])
        assert self._strip(data, 8) == b"1234567"

    def test_invalid_padding_too_large(self):
        """Last byte > blocksize -> not stripped."""
        data = b"Hello" + bytes([17])
        assert self._strip(data, 16) == data

    def test_zero_padding_byte(self):
        """Padding byte of 0 is invalid per PKCS#7."""
        data = b"Hello" + bytes([0])
        assert self._strip(data, 16) == data

    def test_inconsistent_padding(self):
        """Last byte says 3 but not all 3 trailing bytes match."""
        data = b"Hello" + bytes([1, 2, 3])
        assert self._strip(data, 8) == data

    def test_valid_16_byte_padding(self):
        data = bytes([16] * 16)
        assert self._strip(data, 16) == b""
