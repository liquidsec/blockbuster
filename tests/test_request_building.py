"""Tests for URL/body construction across all input/method/format combos."""

from tests.conftest import make_job


class TestBuildRequestGET:
    """GET request URL construction via _buildRequest."""

    def _job(self, **kw):
        j = make_job(httpMethod="GET", **kw)
        j.initialize_client()
        return j

    def test_parameter_mode(self):
        j = self._job(inputMode="parameter", vulnerableParameter="tok")
        method, url, kwargs = j._buildRequest("AAAA")
        assert method == "GET"
        assert "?tok=AAAA" in url
        assert "Cookie" in kwargs["headers"]

    def test_parameter_mode_with_additionals(self):
        j = self._job(
            inputMode="parameter",
            vulnerableParameter="tok",
            additionalParameters={"foo": "bar", "baz": "qux"},
        )
        _, url, _ = j._buildRequest("AAAA")
        assert "tok=AAAA" in url
        assert "&foo=bar" in url
        assert "&baz=qux" in url or "baz=qux" in url

    def test_querystring_mode(self):
        j = self._job(inputMode="querystring")
        _, url, _ = j._buildRequest("MY_CIPHER_TOKEN")
        assert "?MY_CIPHER_TOKEN" in url
        # Should NOT have parameter name
        assert "token=" not in url

    def test_querystring_with_additionals(self):
        j = self._job(inputMode="querystring", additionalParameters={"x": "1"})
        _, url, _ = j._buildRequest("CT")
        assert "?CT" in url
        assert "&x=1" in url

    def test_cookie_mode(self):
        j = self._job(
            inputMode="cookie", vulnerableParameter="auth", cookies={"session": "abc"}
        )
        _, url, kwargs = j._buildRequest("ENCRYPTED")
        # Token should NOT be in URL
        assert "ENCRYPTED" not in url
        # Token should be in cookie header
        assert "auth=ENCRYPTED" in kwargs["headers"]["Cookie"]
        assert "session=abc" in kwargs["headers"]["Cookie"]

    def test_cookie_mode_additionals_use_question_mark(self):
        j = self._job(inputMode="cookie", additionalParameters={"page": "1"})
        _, url, _ = j._buildRequest("CT")
        # First additional should use ? since no query params yet
        assert "?page=1" in url


class TestBuildRequestPOST:
    """POST request body construction."""

    def _job(self, **kw):
        j = make_job(httpMethod="POST", **kw)
        j.initialize_client()
        return j

    def test_form_urlencoded_parameter(self):
        j = self._job(
            inputMode="parameter",
            postFormat="form-urlencoded",
            vulnerableParameter="tok",
        )
        method, url, kwargs = j._buildRequest("AAAA")
        assert method == "POST"
        assert kwargs["data"]["tok"] == "AAAA"
        assert "application/x-www-form-urlencoded" in kwargs["headers"]["Content-Type"]

    def test_form_urlencoded_with_additionals(self):
        j = self._job(
            inputMode="parameter",
            postFormat="form-urlencoded",
            vulnerableParameter="tok",
            additionalParameters={"extra": "val"},
        )
        _, _, kwargs = j._buildRequest("CT")
        assert kwargs["data"]["tok"] == "CT"
        assert kwargs["data"]["extra"] == "val"

    def test_json_parameter(self):
        j = self._job(
            inputMode="parameter", postFormat="json", vulnerableParameter="tok"
        )
        _, _, kwargs = j._buildRequest("AAAA")
        assert kwargs["json"]["tok"] == "AAAA"
        assert "application/json" in kwargs["headers"]["Content-Type"]

    def test_multipart_parameter(self):
        j = self._job(
            inputMode="parameter", postFormat="multipart", vulnerableParameter="tok"
        )
        _, _, kwargs = j._buildRequest("AAAA")
        assert "multipart/form-data" in kwargs["headers"]["Content-Type"]
        assert "tok" in kwargs["data"]  # multipart body contains the field

    def test_querystring_in_post(self):
        j = self._job(inputMode="querystring", postFormat="form-urlencoded")
        _, url, kwargs = j._buildRequest("CT_IN_QS")
        # Token goes in URL, not body
        assert "?CT_IN_QS" in url

    def test_cookie_in_post(self):
        j = self._job(
            inputMode="cookie", postFormat="form-urlencoded", vulnerableParameter="auth"
        )
        _, url, kwargs = j._buildRequest("CT")
        assert "auth=CT" in kwargs["headers"]["Cookie"]
        assert "CT" not in url


class TestMakeRequestCookieHandling:
    """Verify cookie handling doesn't mutate self.cookies."""

    def test_cookies_not_mutated(self):
        j = make_job(
            inputMode="cookie", vulnerableParameter="auth", cookies={"session": "abc"}
        )
        j.initialize_client()
        original_cookies = j.cookies.copy()
        # Just call _buildRequest (which mirrors makeRequest's cookie logic)
        j._buildRequest("test_token")
        assert j.cookies == original_cookies
        assert "auth" not in j.cookies
