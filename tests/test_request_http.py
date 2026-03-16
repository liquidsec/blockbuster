"""Tests for HTTP retry logic, redirect following, and async requests."""

from unittest.mock import patch, AsyncMock

import httpx
import pytest

from tests.conftest import make_job


class TestRetryLogic:
    """Sync makeRequest retry on network errors."""

    def test_retries_on_connect_error_then_succeeds(self):
        j = make_job()
        j.initialize_client()

        call_count = 0

        def fake_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.ConnectError("Connection refused")
            return httpx.Response(200, text="OK")

        with patch.object(j.client, "get", side_effect=fake_get):
            with patch("time.sleep"):  # skip actual waits
                result = j.makeRequest("test_token")

        assert result.status_code == 200
        assert call_count == 3

    def test_raises_after_max_retries(self):
        j = make_job()
        j.initialize_client()

        def always_fail(url, **kwargs):
            raise httpx.ConnectError("Connection refused")

        with patch.object(j.client, "get", side_effect=always_fail):
            with patch("time.sleep"):
                with pytest.raises(httpx.ConnectError):
                    j.makeRequest("test_token")

    def test_retry_backoff_times(self):
        j = make_job()
        j.initialize_client()

        sleep_calls = []
        call_count = 0

        def fake_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.TimeoutException("timeout")
            return httpx.Response(200, text="OK")

        with patch.object(j.client, "get", side_effect=fake_get):
            with patch("time.sleep", side_effect=lambda s: sleep_calls.append(s)):
                j.makeRequest("test_token")

        # Backoff: 2**0=1, 2**1=2
        assert sleep_calls == [1, 2]


class TestRetryLogicAsync:
    """Async makeRequestAsync retry on network errors."""

    @pytest.mark.asyncio
    async def test_retries_then_succeeds(self):
        j = make_job()
        j.initialize_client()

        call_count = 0

        async def fake_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.ConnectError("Connection refused")
            return httpx.Response(200, text="OK")

        with patch.object(j.async_client, "get", side_effect=fake_get):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await j.makeRequestAsync("test_token")

        assert result.status_code == 200
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_raises_after_max_retries(self):
        j = make_job()
        j.initialize_client()

        async def always_fail(url, **kwargs):
            raise httpx.ConnectError("Connection refused")

        with patch.object(j.async_client, "get", side_effect=always_fail):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                with pytest.raises(httpx.ConnectError):
                    await j.makeRequestAsync("test_token")


class TestRedirectFollowing:
    """Sync _followRedirect."""

    def test_follows_302_redirect(self):
        j = make_job()
        j.initialize_client()

        redirect_resp = httpx.Response(
            302,
            headers={"location": "/final"},
            request=httpx.Request("GET", "http://testserver/oracle"),
        )
        final_resp = httpx.Response(200, text="Final page")

        with patch.object(j.client, "get", return_value=final_resp):
            result = j._followRedirect(redirect_resp, {"User-Agent": "test"})

        assert result.status_code == 200
        assert result.text == "Final page"

    def test_returns_non_redirect_immediately(self):
        j = make_job()
        j.initialize_client()

        normal_resp = httpx.Response(
            200,
            text="Not a redirect",
            request=httpx.Request("GET", "http://testserver/oracle"),
        )
        result = j._followRedirect(normal_resp, {})
        assert result.status_code == 200
        assert result.text == "Not a redirect"

    def test_redirect_delay(self):
        j = make_job(redirectDelay=0.5)
        j.initialize_client()

        redirect_resp = httpx.Response(
            302,
            headers={"location": "/final"},
            request=httpx.Request("GET", "http://testserver/oracle"),
        )
        final_resp = httpx.Response(200, text="OK")

        sleep_calls = []
        with patch.object(j.client, "get", return_value=final_resp):
            with patch("time.sleep", side_effect=lambda s: sleep_calls.append(s)):
                j._followRedirect(redirect_resp, {})

        assert sleep_calls == [0.5]

    def test_max_redirects(self):
        j = make_job()
        j.initialize_client()

        # Every response is a redirect
        redirect_resp = httpx.Response(
            302,
            headers={"location": "/loop"},
            request=httpx.Request("GET", "http://testserver/oracle"),
        )

        with patch.object(j.client, "get", return_value=redirect_resp):
            result = j._followRedirect(redirect_resp, {})

        # Should stop after 10 redirects and return the last redirect response
        assert result.status_code == 302

    def test_missing_location_header(self):
        j = make_job()
        j.initialize_client()

        redirect_resp = httpx.Response(
            302, request=httpx.Request("GET", "http://testserver/oracle")
        )
        result = j._followRedirect(redirect_resp, {})
        assert result.status_code == 302


class TestRedirectFollowingAsync:
    """Async _followRedirectAsync."""

    @pytest.mark.asyncio
    async def test_follows_302_redirect(self):
        j = make_job()
        j.initialize_client()

        redirect_resp = httpx.Response(
            302,
            headers={"location": "/final"},
            request=httpx.Request("GET", "http://testserver/oracle"),
        )
        final_resp = httpx.Response(200, text="Final page")

        with patch.object(
            j.async_client, "get", new_callable=AsyncMock, return_value=final_resp
        ):
            result = await j._followRedirectAsync(redirect_resp, {"User-Agent": "test"})

        assert result.text == "Final page"

    @pytest.mark.asyncio
    async def test_redirect_delay_uses_async_sleep(self):
        j = make_job(redirectDelay=1.0)
        j.initialize_client()

        redirect_resp = httpx.Response(
            302,
            headers={"location": "/final"},
            request=httpx.Request("GET", "http://testserver/oracle"),
        )
        final_resp = httpx.Response(200, text="OK")

        sleep_calls = []

        async def fake_sleep(s):
            sleep_calls.append(s)

        with patch.object(
            j.async_client, "get", new_callable=AsyncMock, return_value=final_resp
        ):
            with patch("asyncio.sleep", side_effect=fake_sleep):
                await j._followRedirectAsync(redirect_resp, {})

        assert sleep_calls == [1.0]


class TestRedirectFollowingAsyncMaxRedirects:
    """Async max redirects and final return."""

    @pytest.mark.asyncio
    async def test_max_redirects_async(self):
        j = make_job()
        j.initialize_client()

        redirect_resp = httpx.Response(
            302,
            headers={"location": "/loop"},
            request=httpx.Request("GET", "http://testserver/oracle"),
        )

        async def always_redirect(url, **kwargs):
            return httpx.Response(
                302, headers={"location": "/loop"}, request=httpx.Request("GET", url)
            )

        with patch.object(j.async_client, "get", side_effect=always_redirect):
            result = await j._followRedirectAsync(redirect_resp, {})

        assert result.status_code == 302

    @pytest.mark.asyncio
    async def test_missing_location_async(self):
        j = make_job()
        j.initialize_client()

        redirect_resp = httpx.Response(
            302, request=httpx.Request("GET", "http://testserver/oracle")
        )
        result = await j._followRedirectAsync(redirect_resp, {})
        assert result.status_code == 302


class TestFollowRedirectsFlag:
    """Verify followRedirects=False skips redirect handling."""

    def test_no_redirect_following_when_disabled(self):
        j = make_job(followRedirects=False)
        j.initialize_client()

        redirect_resp = httpx.Response(
            302,
            headers={"location": "/elsewhere"},
            request=httpx.Request("GET", "http://testserver/oracle?token=x"),
        )

        with patch.object(j.client, "get", return_value=redirect_resp):
            result = j.makeRequest("test_token")

        # Should return the 302 directly, not follow it
        assert result.status_code == 302


class TestMakeRequestSyncPaths:
    """Test the actual sync makeRequest URL/body construction paths."""

    def test_get_querystring(self):
        j = make_job(httpMethod="GET", inputMode="querystring")
        j.initialize_client()

        with patch.object(
            j.client, "get", return_value=httpx.Response(200, text="OK")
        ) as mock:
            j.makeRequest("CIPHER_TOKEN")

        url = mock.call_args[0][0]
        assert "?CIPHER_TOKEN" in url

    def test_get_cookie(self):
        j = make_job(
            httpMethod="GET",
            inputMode="cookie",
            vulnerableParameter="auth",
            cookies={"session": "xyz"},
        )
        j.initialize_client()

        with patch.object(
            j.client, "get", return_value=httpx.Response(200, text="OK")
        ) as mock:
            j.makeRequest("ENC_VALUE")

        call_kwargs = mock.call_args
        call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
        assert "auth=ENC_VALUE" in j.headers.get("Cookie", "")

    def test_get_with_additionals(self):
        j = make_job(
            httpMethod="GET",
            inputMode="parameter",
            additionalParameters={"page": "1", "lang": "en"},
        )
        j.initialize_client()

        with patch.object(
            j.client, "get", return_value=httpx.Response(200, text="OK")
        ) as mock:
            j.makeRequest("TOK")

        url = mock.call_args[0][0]
        assert "page=1" in url
        assert "lang=en" in url

    def test_post_form_urlencoded(self):
        j = make_job(
            httpMethod="POST",
            inputMode="parameter",
            postFormat="form-urlencoded",
            vulnerableParameter="data",
        )
        j.initialize_client()

        with patch.object(
            j.client, "post", return_value=httpx.Response(200, text="OK")
        ) as mock:
            j.makeRequest("PAYLOAD")

        kwargs = mock.call_args[1]
        assert kwargs["data"]["data"] == "PAYLOAD"

    def test_post_json(self):
        j = make_job(
            httpMethod="POST",
            inputMode="parameter",
            postFormat="json",
            vulnerableParameter="tok",
        )
        j.initialize_client()

        with patch.object(
            j.client, "post", return_value=httpx.Response(200, text="OK")
        ) as mock:
            j.makeRequest("VAL")

        kwargs = mock.call_args[1]
        assert kwargs["json"]["tok"] == "VAL"

    def test_post_multipart(self):
        j = make_job(
            httpMethod="POST",
            inputMode="parameter",
            postFormat="multipart",
            vulnerableParameter="file",
        )
        j.initialize_client()

        with patch.object(
            j.client, "post", return_value=httpx.Response(200, text="OK")
        ) as mock:
            j.makeRequest("DATA")

        mock.call_args[1]
        assert "multipart/form-data" in mock.call_args[1]["headers"]["Content-Type"]

    def test_post_querystring(self):
        j = make_job(
            httpMethod="POST", inputMode="querystring", postFormat="form-urlencoded"
        )
        j.initialize_client()

        with patch.object(
            j.client, "post", return_value=httpx.Response(200, text="OK")
        ) as mock:
            j.makeRequest("QS_TOKEN")

        url = mock.call_args[0][0]
        assert "?QS_TOKEN" in url

    def test_get_with_follow_redirects(self):
        j = make_job(httpMethod="GET", followRedirects=True)
        j.initialize_client()

        resp = httpx.Response(
            200,
            text="Final",
            request=httpx.Request("GET", "http://testserver/oracle?token=x"),
        )

        with patch.object(j.client, "get", return_value=resp):
            with patch.object(j, "_followRedirect", return_value=resp) as mock_redir:
                j.makeRequest("tok")

        mock_redir.assert_called_once()

    def test_retry_progress_counter(self):
        """Verify progress[1] is incremented on retry."""
        j = make_job()
        j.initialize_client()

        call_count = 0

        def fake_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.ConnectError("fail")
            return httpx.Response(200, text="OK")

        progress = [0, 0]
        with patch.object(j.client, "get", side_effect=fake_get):
            with patch("time.sleep"):
                j.makeRequest("tok", progress=progress)

        assert progress[1] == 2  # Two retries


class TestMakeRequestAsyncPaths:
    """Test async-specific paths in makeRequestAsync."""

    @pytest.mark.asyncio
    async def test_post_path(self):
        j = make_job(
            httpMethod="POST",
            inputMode="parameter",
            postFormat="form-urlencoded",
            vulnerableParameter="tok",
        )
        j.initialize_client()

        async def fake_post(url, **kwargs):
            return httpx.Response(200, text="OK")

        with patch.object(j.async_client, "post", side_effect=fake_post):
            result = await j.makeRequestAsync("VAL")

        assert result.status_code == 200

    @pytest.mark.asyncio
    async def test_follow_redirects_async(self):
        j = make_job(followRedirects=True)
        j.initialize_client()

        resp = httpx.Response(
            200, text="Final", request=httpx.Request("GET", "http://testserver/oracle")
        )

        async def fake_get(url, **kwargs):
            return resp

        with patch.object(j.async_client, "get", side_effect=fake_get):
            with patch.object(
                j, "_followRedirectAsync", new_callable=AsyncMock, return_value=resp
            ) as mock_redir:
                await j.makeRequestAsync("tok")

        mock_redir.assert_called_once()

    @pytest.mark.asyncio
    async def test_retry_progress_async(self):
        j = make_job()
        j.initialize_client()

        call_count = 0

        async def fake_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise httpx.TimeoutException("timeout")
            return httpx.Response(200, text="OK")

        progress = [0, 0]
        with patch.object(j.async_client, "get", side_effect=fake_get):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                await j.makeRequestAsync("tok", progress=progress)

        assert progress[1] == 1
