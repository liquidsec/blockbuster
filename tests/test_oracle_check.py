"""Tests for oracleCheck and oracleSanityCheck."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from tests.conftest import make_job


def mock_response(text):
    """Create a mock HTTP response with a .text attribute."""
    return SimpleNamespace(text=text, status_code=200)


class TestOracleCheck:
    """Test oracleCheck with both oracle modes."""

    def test_search_mode_found(self):
        j = make_job(oracleMode="search", oracleText="success")
        assert j.oracleCheck(mock_response("Operation success!")) is True

    def test_search_mode_not_found(self):
        j = make_job(oracleMode="search", oracleText="success")
        assert j.oracleCheck(mock_response("Error occurred")) is False

    def test_negative_mode_not_found(self):
        """negative mode: True when text is NOT found (valid padding)."""
        j = make_job(oracleMode="negative", oracleText="Invalid padding")
        assert j.oracleCheck(mock_response("OK")) is True

    def test_negative_mode_found(self):
        """negative mode: False when text IS found (invalid padding)."""
        j = make_job(oracleMode="negative", oracleText="Invalid padding")
        assert j.oracleCheck(mock_response("Error: Invalid padding detected")) is False

    def test_case_insensitive_search(self):
        j = make_job(oracleMode="search", oracleText="SUCCESS")
        assert j.oracleCheck(mock_response("operation success!")) is True

    def test_case_insensitive_negative(self):
        j = make_job(oracleMode="negative", oracleText="INVALID PADDING")
        assert j.oracleCheck(mock_response("error: invalid padding")) is False

    def test_empty_response(self):
        j = make_job(oracleMode="search", oracleText="test")
        assert j.oracleCheck(mock_response("")) is False

    def test_empty_oracle_text_search(self):
        """Empty oracle text always matches in search mode."""
        j = make_job(oracleMode="search", oracleText="")
        assert j.oracleCheck(mock_response("anything")) is True

    def test_empty_oracle_text_negative(self):
        """Empty oracle text always found -> negative returns False."""
        j = make_job(oracleMode="negative", oracleText="")
        assert j.oracleCheck(mock_response("anything")) is False


class TestOracleSanityCheck:
    """Test oracleSanityCheck behavior."""

    def test_negative_mode_text_found_passes(self):
        """In negative mode, if oracle text IS found in response to random ct, sanity passes."""
        j = make_job(
            oracleMode="negative", oracleText="Invalid padding", encodingMode="base64"
        )
        j.initialize_client()

        with patch.object(
            j, "makeRequest", return_value=mock_response("Error: Invalid padding")
        ):
            # Should not raise
            j.oracleSanityCheck()

    def test_negative_mode_text_not_found_exits(self):
        """In negative mode, if oracle text NOT found, sanity check fails."""
        j = make_job(
            oracleMode="negative", oracleText="Invalid padding", encodingMode="base64"
        )
        j.initialize_client()

        with patch.object(
            j, "makeRequest", return_value=mock_response("OK - no error here")
        ):
            with pytest.raises(SystemExit) as exc_info:
                j.oracleSanityCheck()
            assert exc_info.value.code == 2

    def test_search_mode_skips(self):
        """In search mode, sanity check is skipped entirely."""
        j = make_job(oracleMode="search", oracleText="success", encodingMode="base64")
        j.initialize_client()

        with patch.object(j, "makeRequest") as mock_req:
            j.oracleSanityCheck()
            mock_req.assert_not_called()
