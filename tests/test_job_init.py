"""Tests for Job.__init__, decryptInit, and encryptInit."""

import base64
import io
import sys

import pytest

from tests.conftest import make_job


class TestJobInit:
    """Verify constructor stores all attributes correctly."""

    def test_all_params_stored(self):
        j = make_job()
        assert j.blocksize == 16
        assert j.mode == "decrypt"
        assert j.debug is False
        assert j.name == "test"
        assert j.ivMode == "firstblock"
        assert j.URL == "http://testserver/oracle"
        assert j.httpMethod == "GET"
        assert j.additionalParameters == {}
        assert j.httpProxyOn is False
        assert j.oracleMode == "negative"
        assert j.oracleText == "Invalid padding"
        assert j.vulnerableParameter == "token"
        assert j.inputMode == "parameter"
        assert j.cookies == {}
        assert j.encodingMode == "base64"
        assert j.postFormat == "form-urlencoded"
        assert j.followRedirects is False

    def test_default_values(self):
        j = make_job()
        assert j.concurrency == 5
        assert j.redirectDelay == 0
        assert j.confirmations == 0
        assert j.plaintextEncoding == "utf-8"
        assert j.anchorCiphertext == ""

    def test_initial_state(self):
        j = make_job()
        assert j.preseeded_intermediates == {}
        assert j.currentBlock == 0
        assert j.solvedBlocks == {}
        assert j.block_solved_intermediates == {}
        assert j.block_solved_values == {}
        assert j.block_currentbyte is None
        assert j.block_padding_num is None

    def test_custom_values(self):
        j = make_job(
            concurrency=50,
            confirmations=3,
            redirectDelay=1.5,
            plaintextEncoding="utf-16-le",
        )
        assert j.concurrency == 50
        assert j.confirmations == 3
        assert j.redirectDelay == 1.5
        assert j.plaintextEncoding == "utf-16-le"


class TestDecryptInit:
    """Test decryptInit block splitting and IV handling."""

    def _init(self, source_string, **kw):
        j = make_job(sourceString=source_string, mode="decrypt", **kw)
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            j.decryptInit()
        finally:
            sys.stdout = old_stdout
        return j

    def test_firstblock_3blocks(self):
        raw = bytes(range(48))
        source = base64.b64encode(raw).decode()
        j = self._init(source, ivMode="firstblock", blocksize=16)
        assert j.iv == list(raw[:16])
        assert j.blockCount == 2
        assert len(j.blocks) == 2
        assert j.blocks[0] == list(raw[16:32])
        assert j.blocks[1] == list(raw[32:48])

    def test_knownIV(self):
        raw = bytes(range(32))
        source = base64.b64encode(raw).decode()
        iv = list(range(200, 216))
        j = self._init(source, ivMode="knownIV", iv=iv, blocksize=16)
        assert j.iv == iv
        assert j.blockCount == 2
        assert j.blocks[0] == list(raw[:16])

    def test_unknown_iv(self):
        raw = bytes(range(32))
        source = base64.b64encode(raw).decode()
        j = self._init(source, ivMode="unknown", blocksize=16)
        assert j.iv == [0] * 16
        assert j.blockCount == 2

    def test_hex_encoding(self):
        raw = bytes(range(48))
        source = raw.hex()
        j = self._init(source, encodingMode="hex", blocksize=16)
        assert j.iv == list(raw[:16])
        assert j.blocks[0] == list(raw[16:32])

    def test_base64url_encoding(self):
        raw = bytes(range(48))
        b64 = base64.b64encode(raw).decode()
        source = b64.replace("+", "-").replace("/", "_").rstrip("=")
        j = self._init(source, encodingMode="base64Url", blocksize=16)
        assert j.iv == list(raw[:16])
        assert j.blockCount == 2

    def test_blocks_are_lists_of_ints(self):
        raw = bytes(range(48))
        source = base64.b64encode(raw).decode()
        j = self._init(source, blocksize=16)
        for block in j.blocks:
            assert isinstance(block, list)
            assert all(isinstance(x, int) for x in block)
            assert len(block) == 16

    def test_blocksize_8(self):
        raw = bytes(range(24))
        source = base64.b64encode(raw).decode()
        j = self._init(source, blocksize=8)
        assert j.iv == list(raw[:8])
        assert j.blockCount == 2
        assert j.blocks[0] == list(raw[8:16])
        assert j.blocks[1] == list(raw[16:24])

    def test_bytemap_preserved(self):
        raw = bytes(range(48))
        source = base64.b64encode(raw).decode()
        j = self._init(source, blocksize=16)
        assert j.bytemap == list(raw)


class TestEncryptInit:
    """Test encryptInit block creation and reversal."""

    def _init(self, source_string, **kw):
        j = make_job(sourceString=source_string, mode="encrypt", **kw)
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            j.encryptInit()
        finally:
            sys.stdout = old_stdout
        return j

    def test_firstblock_basic(self):
        j = self._init("ABCD", ivMode="firstblock", blocksize=16)
        # "ABCD" = 4 bytes, padded to 16 = 1 block
        assert j.blockCount == 1
        assert len(j.blocks) == 1

    def test_blocks_reversed(self):
        """Multi-block: blocks[0] = last plaintext block, blocks[-1] = first."""
        j = self._init("A" * 32, ivMode="firstblock", blocksize=16)
        # 32 bytes + 16 padding = 48 = 3 blocks
        assert j.blockCount == 3
        padded = b"A" * 32 + bytes([16] * 16)
        # encryptInit stores blocks as byte slices from bytemap
        assert list(j.blocks[0]) == list(padded[32:48])  # last block
        assert list(j.blocks[2]) == list(padded[:16])  # first block

    def test_knownIV(self):
        iv = list(range(16))
        j = self._init("Test", ivMode="knownIV", iv=iv, blocksize=16)
        assert j.iv == iv
        assert j.blockCount == 1

    def test_unknown_iv_exits(self):
        with pytest.raises(SystemExit):
            self._init("Test", ivMode="unknown", blocksize=16)

    def test_utf16le_encoding(self):
        j = self._init(
            "AB", ivMode="firstblock", blocksize=16, plaintextEncoding="utf-16-le"
        )
        raw = "AB".encode("utf-16-le")
        assert len(raw) == 4
        assert len(j.bytemap) == 16
        assert bytes(j.bytemap[:4]) == raw

    def test_bytemap_has_correct_padding(self):
        j = self._init("Hello", ivMode="firstblock", blocksize=16)
        # 5 bytes + 11 padding
        assert len(j.bytemap) == 16
        assert j.bytemap[5:] == bytes([11] * 11)

    def test_blocksize_8(self):
        j = self._init("ABCD", ivMode="firstblock", blocksize=8)
        # 4 bytes + 4 padding = 8 = 1 block
        assert j.blockCount == 1
        assert len(j.blocks[0]) == 8

    def test_anchorBlock_mode_base64(self):
        """anchorBlock mode extracts first block of anchorCiphertext as IV."""
        anchor_raw = bytes(range(48))
        anchor_b64 = base64.b64encode(anchor_raw).decode()
        j = self._init(
            "Test", ivMode="anchorBlock", blocksize=16, anchorCiphertext=anchor_b64
        )
        assert j.iv == list(anchor_raw[:16])

    def test_anchorBlock_mode_hex(self):
        anchor_raw = bytes(range(48))
        anchor_hex = anchor_raw.hex()
        j = self._init(
            "Test",
            ivMode="anchorBlock",
            blocksize=16,
            encodingMode="hex",
            anchorCiphertext=anchor_hex,
        )
        assert j.iv == list(anchor_raw[:16])

    def test_anchorBlock_mode_base64url(self):
        anchor_raw = bytes(range(48))
        b64 = base64.b64encode(anchor_raw).decode()
        anchor_b64url = b64.replace("+", "-").replace("/", "_").rstrip("=")
        j = self._init(
            "Test",
            ivMode="anchorBlock",
            blocksize=16,
            encodingMode="base64Url",
            anchorCiphertext=anchor_b64url,
        )
        assert j.iv == list(anchor_raw[:16])


class TestInitialize:
    """Test the initialize() method that ties init + sanity check together."""

    def test_decrypt_initialize(self):
        raw = bytes(range(48))
        source = base64.b64encode(raw).decode()
        j = make_job(sourceString=source, mode="decrypt", oracleMode="search")
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            j.initialize()
        finally:
            sys.stdout = old_stdout
        assert hasattr(j, "blocks")
        assert j.client is not None

    def test_encrypt_initialize(self):
        j = make_job(
            sourceString="Test",
            mode="encrypt",
            ivMode="firstblock",
            oracleMode="search",
        )
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            j.initialize()
        finally:
            sys.stdout = old_stdout
        assert hasattr(j, "blocks")

    def test_invalid_mode_exits(self):
        j = make_job(mode="invalid")
        with pytest.raises(SystemExit):
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                j.initialize()
            finally:
                sys.stdout = old_stdout


class TestDebugMode:
    """Test debug=True constructor and decryptInit paths."""

    def test_debug_constructor(self):
        """debug=True prints extra output."""
        j = make_job(debug=True, sourceString="test_source")
        assert j.debug is True

    def test_encrypt_init_knowniv_prints(self):
        """encryptInit with knownIV prints IV info (line 1018)."""
        iv = list(range(16))
        j = make_job(
            sourceString="Test", mode="encrypt", ivMode="knownIV", iv=iv, debug=False
        )
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            j.encryptInit()
        finally:
            sys.stdout = old_stdout
        output = captured.getvalue()
        assert "Using known IV" in output

    def test_debug_decrypt_init(self):
        """decryptInit with debug=True prints IV and bytemap."""
        raw = bytes(range(48))
        source = base64.b64encode(raw).decode()
        j = make_job(sourceString=source, mode="decrypt", debug=True)
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            j.decryptInit()
        finally:
            sys.stdout = old_stdout
        output = captured.getvalue()
        assert "Initialization Vector" in output or "decimal representation" in output
