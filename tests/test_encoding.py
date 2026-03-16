"""Tests for encodeToken and decode logic in decryptInit."""

import base64
import io
import sys
import urllib.parse


from tests.conftest import make_job


class TestEncodeTokenBase64:
    """base64 encoding mode."""

    def _job(self, **kw):
        return make_job(encodingMode="base64", **kw)

    def test_parameter_mode_url_encodes(self):
        j = self._job(inputMode="parameter")
        raw = bytes(range(16))
        result = j.encodeToken(raw)
        # Should be URL-encoded base64
        decoded = urllib.parse.unquote_plus(result)
        assert base64.b64decode(decoded) == raw

    def test_querystring_mode_no_url_encoding(self):
        j = self._job(inputMode="querystring")
        # Use bytes that produce + and / in base64
        raw = b"\xfb\xff\xfe"  # produces +//+ in base64
        result = j.encodeToken(raw)
        # Should be raw base64 (no URL encoding)
        assert (
            "+" in result or "/" in result or result == base64.b64encode(raw).decode()
        )
        assert base64.b64decode(result) == raw

    def test_cookie_mode_url_encodes(self):
        j = self._job(inputMode="cookie")
        raw = bytes(range(16))
        result = j.encodeToken(raw)
        decoded = urllib.parse.unquote_plus(result)
        assert base64.b64decode(decoded) == raw

    def test_round_trip(self):
        j = self._job(inputMode="parameter")
        for size in [0, 1, 8, 16, 32, 48]:
            raw = bytes(range(size % 256)) if size > 0 else b""
            if size > 0:
                raw = bytes([i % 256 for i in range(size)])
            encoded = j.encodeToken(raw)
            decoded_str = urllib.parse.unquote_plus(encoded)
            assert base64.b64decode(decoded_str) == raw


class TestEncodeTokenBase64Url:
    """base64Url encoding mode."""

    def test_strips_padding(self):
        j = make_job(encodingMode="base64Url")
        raw = b"\xff"  # base64 = "/w==" -> base64url = "_w"
        result = j.encodeToken(raw)
        assert "=" not in result

    def test_replaces_plus_and_slash(self):
        j = make_job(encodingMode="base64Url")
        # Find bytes that produce + or / in standard base64
        raw = b"\xfb\xef\xbe"  # base64 of this contains + and /
        base64.b64encode(raw).decode()
        result = j.encodeToken(raw)
        assert "+" not in result
        assert "/" not in result
        # Reverse: replace back and add padding
        reversed_b64 = result.replace("-", "+").replace("_", "/")
        reversed_b64 += "=" * (len(reversed_b64) % 4)
        assert base64.b64decode(reversed_b64) == raw

    def test_round_trip(self):
        j = make_job(encodingMode="base64Url")
        raw = bytes(range(32))
        encoded = j.encodeToken(raw)
        # Decode base64url
        decoded_b64 = encoded.replace("-", "+").replace("_", "/")
        decoded_b64 += "=" * (len(decoded_b64) % 4)
        assert base64.b64decode(decoded_b64) == raw


class TestEncodeTokenHex:
    """hex encoding mode."""

    def test_uppercase_hex(self):
        j = make_job(encodingMode="hex")
        raw = bytes([0xAB, 0xCD, 0xEF])
        assert j.encodeToken(raw) == "ABCDEF"

    def test_round_trip(self):
        j = make_job(encodingMode="hex")
        raw = bytes(range(16))
        result = j.encodeToken(raw)
        assert bytes.fromhex(result) == raw

    def test_empty_bytes(self):
        j = make_job(encodingMode="hex")
        assert j.encodeToken(b"") == ""


# ---------------------------------------------------------------------------
# decryptInit decode + block splitting
# ---------------------------------------------------------------------------


class TestDecryptInitDecoding:
    """Test that decryptInit correctly decodes various encoding modes and splits blocks."""

    def _init_job(
        self,
        source_string,
        encoding_mode="base64",
        iv_mode="firstblock",
        blocksize=16,
        iv=None,
    ):
        kw = dict(
            sourceString=source_string,
            mode="decrypt",
            encodingMode=encoding_mode,
            ivMode=iv_mode,
            blocksize=blocksize,
        )
        if iv is not None:
            kw["iv"] = iv
        j = make_job(**kw)
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            j.decryptInit()
        finally:
            sys.stdout = old_stdout
        return j

    def test_base64_firstblock_3blocks(self):
        """48 bytes = 3 blocks. First block = IV, remaining 2 = data blocks."""
        raw = bytes(range(48))
        source = base64.b64encode(raw).decode()
        j = self._init_job(source)
        assert j.iv == list(raw[:16])
        assert j.blockCount == 2
        assert j.blocks[0] == list(raw[16:32])
        assert j.blocks[1] == list(raw[32:48])

    def test_base64_knownIV(self):
        """32 bytes, knownIV mode. All bytes go to blocks."""
        raw = bytes(range(32))
        source = base64.b64encode(raw).decode()
        iv = list(range(100, 116))
        j = self._init_job(source, iv_mode="knownIV", iv=iv)
        assert j.iv == iv
        assert j.blockCount == 2
        assert j.blocks[0] == list(raw[:16])
        assert j.blocks[1] == list(raw[16:32])

    def test_base64_unknown_iv(self):
        """unknown mode: IV set to zeros."""
        raw = bytes(range(32))
        source = base64.b64encode(raw).decode()
        j = self._init_job(source, iv_mode="unknown")
        assert j.iv == [0] * 16
        assert j.blockCount == 2

    def test_hex_encoding(self):
        raw = bytes(range(48))
        source = raw.hex()
        j = self._init_job(source, encoding_mode="hex")
        assert j.iv == list(raw[:16])
        assert j.blockCount == 2
        assert j.blocks[0] == list(raw[16:32])

    def test_base64url_encoding(self):
        raw = bytes(range(48))
        b64 = base64.b64encode(raw).decode()
        source = b64.replace("+", "-").replace("/", "_").rstrip("=")
        j = self._init_job(source, encoding_mode="base64Url")
        assert j.iv == list(raw[:16])
        assert j.blockCount == 2

    def test_url_encoded_source(self):
        """Source string may be URL-encoded (e.g., copied from a URL)."""
        raw = bytes(range(48))
        b64 = base64.b64encode(raw).decode()
        source = urllib.parse.quote_plus(b64)
        j = self._init_job(source)
        assert j.iv == list(raw[:16])
        assert j.blockCount == 2

    def test_base64_padding_restoration(self):
        """Base64 strings with stripped padding should still decode correctly."""
        raw = bytes(range(17))  # 17 bytes -> base64 has padding
        b64 = base64.b64encode(raw).decode()
        stripped = b64.rstrip("=")
        # decryptInit adds padding back
        j = make_job(
            sourceString=stripped,
            mode="decrypt",
            encodingMode="base64",
            ivMode="unknown",
            blocksize=16,
        )
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            j.decryptInit()
        finally:
            sys.stdout = old_stdout
        assert j.bytemap == list(raw)

    def test_blocksize_8(self):
        """Test with blocksize=8 (DES-like)."""
        raw = bytes(range(24))  # 3 blocks of 8
        source = base64.b64encode(raw).decode()
        j = self._init_job(source, blocksize=8)
        assert j.iv == list(raw[:8])
        assert j.blockCount == 2
        assert j.blocks[0] == list(raw[8:16])
        assert j.blocks[1] == list(raw[16:24])
