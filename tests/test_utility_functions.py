"""Tests for pure utility functions in blockbuster."""

import base64
import pickle

import pytest

from blockbuster.blockbuster import (
    makeCookieString,
    encode_multipart,
    split_by_n,
    bytes_to_base64,
    b64urlEncode,
    handleError,
    saveState,
)


# ---------------------------------------------------------------------------
# makeCookieString
# ---------------------------------------------------------------------------


class TestMakeCookieString:
    def test_empty_dict(self):
        assert makeCookieString({}) == ""

    def test_single_cookie(self):
        assert makeCookieString({"a": "b"}) == "a=b;"

    def test_multiple_cookies(self):
        result = makeCookieString({"a": "1", "b": "2"})
        assert "a=1;" in result
        assert "b=2;" in result

    def test_special_chars_passthrough(self):
        result = makeCookieString({"key": "val=ue;extra"})
        assert "key=val=ue;extra;" == result


# ---------------------------------------------------------------------------
# encode_multipart
# ---------------------------------------------------------------------------


class TestEncodeMultipart:
    def test_single_field(self):
        body, ct = encode_multipart({"name": "value"})
        assert "Content-Disposition: form-data" in body
        assert 'name="name"' in body
        assert "value" in body
        assert "multipart/form-data; boundary=" in ct

    def test_boundary_in_body_and_content_type(self):
        body, ct = encode_multipart({"x": "y"})
        boundary = ct.split("boundary=")[1]
        assert f"--{boundary}" in body
        assert body.endswith(f"--{boundary}--\r\n")

    def test_multiple_fields(self):
        body, _ = encode_multipart({"a": "1", "b": "2"})
        assert 'name="a"' in body
        assert 'name="b"' in body


# ---------------------------------------------------------------------------
# split_by_n
# ---------------------------------------------------------------------------


class TestSplitByN:
    def test_even_split(self):
        assert list(split_by_n("abcdef", 2)) == ["ab", "cd", "ef"]

    def test_uneven_split(self):
        assert list(split_by_n("abcde", 2)) == ["ab", "cd", "e"]

    def test_n_equals_1(self):
        assert list(split_by_n("abc", 1)) == ["a", "b", "c"]

    def test_n_larger_than_seq(self):
        assert list(split_by_n("ab", 5)) == ["ab"]

    def test_empty_sequence(self):
        assert list(split_by_n("", 3)) == []

    def test_bytes_input(self):
        assert list(split_by_n(b"\x00\x01\x02\x03", 2)) == [b"\x00\x01", b"\x02\x03"]

    def test_list_input(self):
        assert list(split_by_n([1, 2, 3, 4, 5, 6], 3)) == [[1, 2, 3], [4, 5, 6]]


# ---------------------------------------------------------------------------
# bytes_to_base64
# ---------------------------------------------------------------------------


class TestBytesToBase64:
    def test_known_value(self):
        result = bytes_to_base64(b"\x00\x01\x02")
        assert result == base64.b64encode(b"\x00\x01\x02")

    def test_returns_bytes(self):
        result = bytes_to_base64(b"hello")
        assert isinstance(result, bytes)

    def test_empty_bytes(self):
        result = bytes_to_base64(b"")
        assert result == b""

    def test_padding(self):
        # 1 byte -> 2 padding chars
        result = bytes_to_base64(b"\xff")
        assert result.endswith(b"==")

        # 2 bytes -> 1 padding char
        result = bytes_to_base64(b"\xff\xff")
        assert result.endswith(b"=")

        # 3 bytes -> no padding
        result = bytes_to_base64(b"\xff\xff\xff")
        assert not result.endswith(b"=")


# ---------------------------------------------------------------------------
# b64urlEncode
# ---------------------------------------------------------------------------


class TestB64urlEncode:
    def test_replaces_slash(self):
        assert b64urlEncode("abc/def") == "abc%2Fdef"

    def test_replaces_plus(self):
        assert b64urlEncode("abc+def") == "abc%2Bdef"

    def test_replaces_both(self):
        assert b64urlEncode("a+b/c") == "a%2Bb%2Fc"

    def test_no_special_chars(self):
        assert b64urlEncode("abcdef") == "abcdef"

    def test_empty_string(self):
        assert b64urlEncode("") == ""


# ---------------------------------------------------------------------------
# handleError
# ---------------------------------------------------------------------------


class TestHandleError:
    def test_exits_with_code_2(self):
        with pytest.raises(SystemExit) as exc_info:
            handleError("test error message")
        assert exc_info.value.code == 2

    def test_prints_message(self, capsys):
        with pytest.raises(SystemExit):
            handleError("my error")
        captured = capsys.readouterr()
        assert "my error" in captured.out


# ---------------------------------------------------------------------------
# saveState
# ---------------------------------------------------------------------------


class TestSaveState:
    def _make_job(self, **overrides):
        """Create a real Job instance for saveState testing."""
        from tests.conftest import make_job

        j = make_job(name="testjob", **overrides)
        # Override attributes that saveState checks
        if "currentBlock" in overrides:
            j.currentBlock = overrides["currentBlock"]
        if "blockCount" in overrides:
            j.blockCount = overrides["blockCount"]
        if "block_solved_intermediates" in overrides:
            j.block_solved_intermediates = overrides["block_solved_intermediates"]
        return j

    def test_creates_pickle_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        job = self._make_job()
        job.blockCount = 3
        saveState(job)
        files = list(tmp_path.glob("blockbuster-state-*.pkl"))
        assert len(files) == 1

    def test_filename_contains_block_number(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        job = self._make_job()
        job.currentBlock = 2
        job.blockCount = 5
        saveState(job)
        files = list(tmp_path.glob("*.pkl"))
        assert "BLOCK_2" in files[0].name

    def test_filename_final_when_complete(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        job = self._make_job()
        job.currentBlock = 3
        job.blockCount = 3
        saveState(job)
        files = list(tmp_path.glob("*.pkl"))
        assert "BLOCK_FINAL" in files[0].name

    def test_filename_has_byte_suffix(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        job = self._make_job()
        job.currentBlock = 1
        job.blockCount = 3
        job.block_solved_intermediates = {15: 0x42, 14: 0x33}
        saveState(job)
        files = list(tmp_path.glob("*.pkl"))
        assert "BYTE_2" in files[0].name

    def test_no_byte_suffix_on_final(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        job = self._make_job()
        job.currentBlock = 3
        job.blockCount = 3
        job.block_solved_intermediates = {15: 0x42}
        saveState(job)
        files = list(tmp_path.glob("*.pkl"))
        assert "BYTE" not in files[0].name

    def test_pickle_is_loadable(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        job = self._make_job()
        job.blockCount = 3
        job.extra_data = "hello"
        saveState(job)
        files = list(tmp_path.glob("*.pkl"))
        with open(files[0], "rb") as f:
            loaded = pickle.load(f)
        assert loaded.name == "testjob"
        assert loaded.extra_data == "hello"
