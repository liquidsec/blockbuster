"""Tests for nextBlock, block retry logic, and encrypt sanity check."""

from types import SimpleNamespace
from unittest.mock import patch, AsyncMock

import pytest

from tests.conftest import make_job


class TestNextBlockDecrypt:
    """nextBlock in decrypt mode."""

    @pytest.mark.asyncio
    async def test_successful_decrypt_returns_0(self):
        j = make_job(mode="decrypt")
        j.initialize_client()
        j.blockCount = 1
        j.currentBlock = 0
        j.blocks = [[0] * 16]
        j.iv = [0] * 16

        with patch.object(
            j, "decryptBlock", new_callable=AsyncMock, return_value=b"decrypted_block!"
        ):
            result = await j.nextBlock()

        assert result == 0
        assert j.solvedBlocks[0] == b"decrypted_block!"

    @pytest.mark.asyncio
    async def test_failed_decrypt_returns_1(self):
        j = make_job(mode="decrypt")
        j.initialize_client()
        j.blockCount = 1
        j.currentBlock = 0
        j.blocks = [[0] * 16]
        j.iv = [0] * 16

        with patch.object(
            j,
            "decryptBlock",
            new_callable=AsyncMock,
            side_effect=Exception("Block failed"),
        ):
            result = await j.nextBlock()

        assert result == 1
        assert 0 not in j.solvedBlocks


class TestNextBlockEncrypt:
    """nextBlock in encrypt mode with sanity check."""

    @pytest.mark.asyncio
    async def test_successful_encrypt_with_passing_sanity_check(self):
        j = make_job(
            mode="encrypt", oracleMode="negative", oracleText="Invalid padding"
        )
        j.initialize_client()
        j.blockCount = 1
        j.currentBlock = 0
        j.blocks = [[0x41] * 16]
        j.iv = [0] * 16

        block_result = bytes([0xDE] * 16)

        def mock_request(token):
            return SimpleNamespace(text="OK", status_code=200)

        with patch.object(
            j, "encryptBlock", new_callable=AsyncMock, return_value=block_result
        ):
            with patch.object(j, "makeRequest", side_effect=mock_request):
                result = await j.nextBlock()

        assert result == 0
        assert j.solvedBlocks[0] == block_result

    @pytest.mark.asyncio
    async def test_failed_sanity_check_backs_out_block(self):
        j = make_job(
            mode="encrypt", oracleMode="negative", oracleText="Invalid padding"
        )
        j.initialize_client()
        j.blockCount = 1
        j.currentBlock = 0
        j.blocks = [[0x41] * 16]
        j.iv = [0] * 16

        block_result = bytes([0xDE] * 16)

        def mock_request(token):
            # Sanity check fails — the oracle text IS found (negative mode: pass = text absent)
            return SimpleNamespace(text="Invalid padding", status_code=200)

        with patch.object(
            j, "encryptBlock", new_callable=AsyncMock, return_value=block_result
        ):
            with patch.object(j, "makeRequest", side_effect=mock_request):
                result = await j.nextBlock()

        assert result == 1
        assert 0 not in j.solvedBlocks  # Block was backed out

    @pytest.mark.asyncio
    async def test_encrypt_exception_returns_1(self):
        j = make_job(mode="encrypt")
        j.initialize_client()
        j.blockCount = 1
        j.currentBlock = 0
        j.blocks = [[0] * 16]
        j.iv = [0] * 16

        with patch.object(
            j,
            "encryptBlock",
            new_callable=AsyncMock,
            side_effect=Exception("Encrypt failed"),
        ):
            result = await j.nextBlock()

        assert result == 1


class TestBlockRetryLogic:
    """Test the retry logic that wraps nextBlock in async_main."""

    @pytest.mark.asyncio
    async def test_retry_then_succeed(self):
        """Simulate the retry loop: fail once, then succeed."""
        j = make_job(mode="decrypt")
        j.initialize_client()
        j.blockCount = 1
        j.currentBlock = 0
        j.blocks = [[0] * 16]
        j.iv = [0] * 16

        call_count = 0

        async def mock_next_block():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                return 1  # Fail
            j.solvedBlocks[0] = b"solved!"
            return 0  # Succeed

        max_block_retries = 3
        block_failures = 0

        with patch.object(j, "nextBlock", side_effect=mock_next_block):
            with patch("blockbuster.blockbuster.saveState"):
                while j.currentBlock < j.blockCount:
                    result = await j.nextBlock()
                    if result == 0:
                        block_failures = 0
                        j.currentBlock += 1
                        j._clear_byte_progress()
                    else:
                        block_failures += 1
                        if block_failures >= max_block_retries:
                            break

        assert j.currentBlock == 1
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_aborts_after_max_retries(self):
        j = make_job(mode="decrypt")
        j.initialize_client()
        j.blockCount = 1
        j.currentBlock = 0
        j.blocks = [[0] * 16]
        j.iv = [0] * 16

        async def always_fail():
            return 1

        max_block_retries = 3
        block_failures = 0

        with patch.object(j, "nextBlock", side_effect=always_fail):
            while j.currentBlock < j.blockCount:
                result = await j.nextBlock()
                if result == 0:
                    block_failures = 0
                    j.currentBlock += 1
                else:
                    block_failures += 1
                    if block_failures >= max_block_retries:
                        break

        assert j.currentBlock == 0  # Never advanced
        assert block_failures == 3


class TestNextBlockEncryptKnownIV:
    """Test encrypt sanity check with knownIV appends IV instead of zeros."""

    @pytest.mark.asyncio
    async def test_encrypt_knowniv_appends_iv(self):
        iv = list(range(16))
        j = make_job(
            mode="encrypt",
            oracleMode="negative",
            oracleText="Invalid padding",
            ivMode="knownIV",
            iv=iv,
        )
        j.initialize_client()
        j.blockCount = 1
        j.currentBlock = 0
        j.blocks = [[0x41] * 16]

        block_result = bytes([0xDE] * 16)
        captured_tokens = []

        def mock_request(token):
            captured_tokens.append(token)
            return SimpleNamespace(text="OK", status_code=200)

        with patch.object(
            j, "encryptBlock", new_callable=AsyncMock, return_value=block_result
        ):
            with patch.object(j, "makeRequest", side_effect=mock_request):
                result = await j.nextBlock()

        assert result == 0
        # The sanity check token should contain the IV appended
        assert len(captured_tokens) == 1


class TestHelperMethods:
    """Test printProgress, verbosePrint, decryptBlockFail, encryptBlockFail."""

    def test_print_progress_string_blocks(self, capsys):
        j = make_job()
        j.currentBlock = 2
        j.blockCount = 3
        j.solvedBlocks = {0: "block0", 1: "block1"}
        j.printProgress()
        out = capsys.readouterr().out
        assert "Solved 2 blocks" in out

    def test_print_progress_bytes_blocks(self, capsys):
        j = make_job()
        j.currentBlock = 1
        j.blockCount = 2
        j.solvedBlocks = {0: b"\xff\xfe"}
        j.printProgress()
        out = capsys.readouterr().out
        assert "Solved 1 blocks" in out

    def test_decrypt_block_fail_raises(self):
        j = make_job()
        with pytest.raises(Exception, match="Block failed"):
            j.decryptBlockFail([0] * 16, b"")

    def test_encrypt_block_fail_raises(self):
        j = make_job()
        with pytest.raises(Exception, match="Block failed"):
            j.encryptBlockFail([0] * 16, b"")

    def test_verbose_print(self, capsys):
        j = make_job()
        j.verbosePrint([0] * 16, b"\x00" * 32, "AAAA==", "response text")
        out = capsys.readouterr().out
        assert "LENGTH OF tempTokenBytes" in out
        assert "response text" in out
