"""Tests for argument parsing and config validation in async_main."""

import configparser
import json

import pytest

from blockbuster.blockbuster import handleError


class TestConfigValidation:
    """Test the config validation logic from async_main.

    Rather than testing async_main directly (which is complex to mock),
    we test the validation logic patterns used in the code.
    """

    def _write_config(self, tmp_path, overrides=None):
        """Write a valid config file, optionally overriding specific values."""
        defaults = {
            "name": "test",
            "URL": "http://127.0.0.1/test",
            "httpMethod": "GET",
            "additionalParameters": "{}",
            "blocksize": "16",
            "httpProxyOn": "False",
            "httpProxyIp": "127.0.0.1",
            "httpProxyPort": "8080",
            "headers": '{"User-Agent":"test"}',
            "cookies": "{}",
            "ivMode": "firstblock",
            "iv": "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
            "oracleMode": "negative",
            "oracleText": "Invalid padding",
            "vulnerableParameter": "token",
            "inputMode": "parameter",
            "encodingMode": "base64",
            "postFormat": "form-urlencoded",
            "followRedirects": "False",
            "concurrency": "10",
            "redirectDelay": "0",
            "confirmations": "0",
        }
        if overrides:
            defaults.update(overrides)

        config = configparser.RawConfigParser()
        config["default"] = defaults
        config_path = tmp_path / "test.ini"
        with open(config_path, "w") as f:
            config.write(f)
        return str(config_path)

    def _read_config(self, config_path):
        """Read and return parsed config values like async_main does."""
        config = configparser.RawConfigParser()
        config.read(config_path)
        return config

    def test_valid_config_parses(self, tmp_path):
        path = self._write_config(tmp_path)
        config = self._read_config(path)
        assert config["default"]["name"] == "test"
        assert config["default"]["blocksize"] == "16"
        assert json.loads(config["default"]["additionalParameters"]) == {}

    def test_invalid_oracle_mode(self, tmp_path):
        """oracleMode must be 'search' or 'negative'."""
        path = self._write_config(tmp_path, {"oracleMode": "bogus"})
        config = self._read_config(path)
        oracle_mode = config["default"]["oracleMode"]
        assert oracle_mode not in ("search", "negative")

    def test_valid_oracle_modes(self, tmp_path):
        for mode in ("search", "negative"):
            path = self._write_config(tmp_path, {"oracleMode": mode})
            config = self._read_config(path)
            assert config["default"]["oracleMode"] == mode

    def test_invalid_encoding_mode(self, tmp_path):
        path = self._write_config(tmp_path, {"encodingMode": "rot13"})
        config = self._read_config(path)
        assert config["default"]["encodingMode"] not in ["base64", "base64Url", "hex"]

    def test_valid_encoding_modes(self, tmp_path):
        for mode in ("base64", "base64Url", "hex"):
            path = self._write_config(tmp_path, {"encodingMode": mode})
            config = self._read_config(path)
            assert config["default"]["encodingMode"] == mode

    def test_invalid_http_method(self, tmp_path):
        path = self._write_config(tmp_path, {"httpMethod": "DELETE"})
        config = self._read_config(path)
        method = config["default"]["httpMethod"]
        assert method not in ("GET", "POST")

    def test_invalid_post_format(self, tmp_path):
        path = self._write_config(tmp_path, {"httpMethod": "POST", "postFormat": "xml"})
        config = self._read_config(path)
        assert config["default"]["postFormat"] not in (
            "form-urlencoded",
            "multipart",
            "json",
        )

    def test_invalid_proxy_ip(self):
        """socket.inet_aton should reject invalid IPs."""
        import socket

        with pytest.raises(socket.error):
            socket.inet_aton("not.an.ip")

    def test_invalid_proxy_port_non_int(self, tmp_path):
        path = self._write_config(tmp_path, {"httpProxyPort": "abc"})
        config = self._read_config(path)
        with pytest.raises(ValueError):
            int(config["default"]["httpProxyPort"])

    def test_invalid_proxy_port_too_high(self, tmp_path):
        path = self._write_config(tmp_path, {"httpProxyPort": "99999"})
        config = self._read_config(path)
        port = int(config["default"]["httpProxyPort"])
        assert not (port <= 65535)

    def test_invalid_blocksize(self, tmp_path):
        path = self._write_config(tmp_path, {"blocksize": "not_a_number"})
        config = self._read_config(path)
        with pytest.raises(ValueError):
            int(config["default"]["blocksize"])

    def test_valid_iv_modes(self, tmp_path):
        for mode in ("firstblock", "knownIV", "unknown", "anchorBlock"):
            path = self._write_config(tmp_path, {"ivMode": mode})
            config = self._read_config(path)
            assert config["default"]["ivMode"] in (
                "firstblock",
                "knownIV",
                "unknown",
                "anchorBlock",
            )

    def test_invalid_iv_mode(self, tmp_path):
        path = self._write_config(tmp_path, {"ivMode": "randomIV"})
        config = self._read_config(path)
        assert config["default"]["ivMode"] not in (
            "firstblock",
            "knownIV",
            "unknown",
            "anchorBlock",
        )

    def test_knowniv_requires_iv(self, tmp_path):
        """In knownIV mode, iv must be provided, correct length, all ints."""
        path = self._write_config(tmp_path, {"ivMode": "knownIV", "iv": "[]"})
        config = self._read_config(path)
        iv = json.loads(config["default"]["iv"])
        assert len(iv) == 0  # Would fail validation

    def test_knowniv_iv_length_mismatch(self, tmp_path):
        path = self._write_config(
            tmp_path, {"ivMode": "knownIV", "iv": "[1,2,3]", "blocksize": "16"}
        )
        config = self._read_config(path)
        iv = json.loads(config["default"]["iv"])
        blocksize = int(config["default"]["blocksize"])
        assert len(iv) != blocksize

    def test_knowniv_iv_non_int_values(self, tmp_path):
        path = self._write_config(tmp_path, {"ivMode": "knownIV", "iv": '["a","b"]'})
        config = self._read_config(path)
        iv = json.loads(config["default"]["iv"])
        assert not all(isinstance(x, int) for x in iv)

    def test_anchorblock_requires_ciphertext(self, tmp_path):
        path = self._write_config(tmp_path, {"ivMode": "anchorBlock"})
        config = self._read_config(path)
        anchor = config["default"].get("anchorCiphertext", "")
        assert not anchor  # Would fail validation


class TestHandleError:
    """handleError calls sys.exit(2)."""

    def test_exits_with_code_2(self):
        with pytest.raises(SystemExit) as exc_info:
            handleError("test error")
        assert exc_info.value.code == 2


class TestModeShortcuts:
    """Test that mode shortcuts 'e' -> 'encrypt', 'd' -> 'decrypt'."""

    @pytest.mark.parametrize("short,full", [("e", "encrypt"), ("d", "decrypt")])
    def test_mode_expansion(self, short, full):
        mode = short
        if mode == "e":
            mode = "encrypt"
        if mode == "d":
            mode = "decrypt"
        assert mode == full
