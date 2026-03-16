"""Shared fixtures for the blockbuster test suite."""

import base64
import io
import sys

import httpx
import pytest
import respx
from Crypto.Cipher import AES

from blockbuster.blockbuster import Job

# ---------------------------------------------------------------------------
# AES-CBC padding oracle simulator
# ---------------------------------------------------------------------------


class PaddingOracle:
    """A simulated AES-CBC padding oracle for deterministic offline testing."""

    def __init__(self, key: bytes, iv: bytes, blocksize: int = 16):
        self.key = key
        self.iv = iv
        self.blocksize = blocksize

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext with PKCS#7 padding. Returns IV + ciphertext."""
        pad_len = self.blocksize - (len(plaintext) % self.blocksize)
        if pad_len == 0:
            pad_len = self.blocksize
        padded = plaintext + bytes([pad_len] * pad_len)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        ct = cipher.encrypt(padded)
        return self.iv + ct

    def check_padding(self, ciphertext_with_iv: bytes) -> bool:
        """Decrypt and check PKCS#7 padding validity.

        *ciphertext_with_iv* should be IV (blocksize bytes) followed by ciphertext.
        """
        if len(ciphertext_with_iv) < self.blocksize * 2:
            return False
        iv = ciphertext_with_iv[: self.blocksize]
        ct = ciphertext_with_iv[self.blocksize :]
        if len(ct) % self.blocksize != 0:
            return False
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ct)
        pad_byte = plaintext[-1]
        if pad_byte < 1 or pad_byte > self.blocksize:
            return False
        return all(b == pad_byte for b in plaintext[-pad_byte:])


# Fixed test key / IV for reproducible tests
AES_KEY = bytes(range(16))  # 0x00..0x0f
AES_IV = bytes(range(16, 32))  # 0x10..0x1f
ORACLE = PaddingOracle(AES_KEY, AES_IV, blocksize=16)


# ---------------------------------------------------------------------------
# Job factory
# ---------------------------------------------------------------------------

JOB_DEFAULTS = dict(
    blocksize=16,
    mode="decrypt",
    debug=False,
    sourceString="",
    name="test",
    ivMode="firstblock",
    URL="http://testserver/oracle",
    httpMethod="GET",
    additionalParameters={},
    httpProxyOn=False,
    httpProxyIp="127.0.0.1",
    httpProxyPort=8080,
    headers={"User-Agent": "pytest"},
    iv=[0] * 16,
    oracleMode="negative",
    oracleText="Invalid padding",
    vulnerableParameter="token",
    inputMode="parameter",
    cookies={},
    encodingMode="base64",
    postFormat="form-urlencoded",
    followRedirects=False,
    concurrency=5,
    redirectDelay=0,
    confirmations=0,
    plaintextEncoding="utf-8",
    anchorCiphertext="",
)


def make_job(**overrides) -> Job:
    """Create a Job instance, suppressing the noisy constructor output."""
    kw = {**JOB_DEFAULTS, **overrides}
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        job = Job(**kw)
    finally:
        sys.stdout = old_stdout
    return job


@pytest.fixture
def job_factory():
    """Fixture that returns the ``make_job`` helper."""
    return make_job


@pytest.fixture
def oracle():
    """A PaddingOracle instance using the fixed test key/IV."""
    return ORACLE


@pytest.fixture
def encrypted_hello(oracle):
    """Returns base64-encoded IV+ciphertext for b'Hello World!!!!!' (16 bytes -> 32 bytes ct + 16 bytes IV)."""
    ct = oracle.encrypt(b"Hello World!!!!!")
    return base64.b64encode(ct).decode()


# ---------------------------------------------------------------------------
# respx-based mock HTTP oracle
# ---------------------------------------------------------------------------


def _make_oracle_route(
    oracle_obj,
    encoding_mode="base64",
    input_mode="parameter",
    vuln_param="token",
    oracle_text="Invalid padding",
):
    """Return a respx side-effect function that simulates a padding oracle."""

    def _handler(request: httpx.Request) -> httpx.Response:
        # Extract the ciphertext token from the request
        url = str(request.url)
        token = None

        if input_mode == "parameter":
            from urllib.parse import parse_qs, urlparse

            qs = parse_qs(urlparse(url).query)
            token = qs.get(vuln_param, [None])[0]
        elif input_mode == "querystring":
            from urllib.parse import urlparse

            token = urlparse(url).query
        elif input_mode == "cookie":
            cookie_header = request.headers.get("cookie", "")
            for part in cookie_header.split(";"):
                part = part.strip()
                if part.startswith(vuln_param + "="):
                    token = part[len(vuln_param) + 1 :]
                    break

        if token is None:
            return httpx.Response(400, text="Missing token")

        # Decode
        import urllib.parse as up

        if encoding_mode == "base64":
            raw = up.unquote_plus(token)
            raw += "=" * (len(raw) % 4)
            ct_bytes = base64.b64decode(raw)
        elif encoding_mode == "base64Url":
            raw = token.replace("-", "+").replace("_", "/")
            raw += "=" * (len(raw) % 4)
            ct_bytes = base64.b64decode(raw)
        elif encoding_mode == "hex":
            ct_bytes = bytes.fromhex(token)
        else:
            return httpx.Response(500, text="Unknown encoding")

        valid = oracle_obj.check_padding(ct_bytes)

        if valid:
            return httpx.Response(200, text="OK")
        else:
            return httpx.Response(200, text=f"Error: {oracle_text}")

    return _handler


@pytest.fixture
def mock_oracle_server(oracle):
    """Activate a respx mock that simulates a negative-mode padding oracle at http://testserver/oracle."""
    handler = _make_oracle_route(oracle)
    with respx.mock(assert_all_called=False) as rsp:
        rsp.route(url__startswith="http://testserver/oracle").mock(side_effect=handler)
        yield rsp
