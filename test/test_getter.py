from falcon import Request
from falcon import RequestOptions
from falcon import testing
import pytest

from falcon_auth2 import BackendNotApplicable
from falcon_auth2 import getter
from falcon_auth2.utils import await_
from falcon_auth2.utils import greenlet_spawn


def make_request(**kw):
    return Request(testing.create_environ(**kw))


async def check_challenges(getter, req, err, match, challenges):
    with pytest.raises(BackendNotApplicable, match=match) as err:
        getter.load(req, challenges=challenges)
    if not challenges:
        assert err.value.headers is None or "WWW-Authenticate" not in err.value.headers
    else:
        assert err.value.headers["WWW-Authenticate"] == ", ".join(challenges)
    with pytest.raises(BackendNotApplicable, match=match) as err:
        await getter.load_async(req, challenges=challenges)
    if not challenges:
        assert err.value.headers is None or "WWW-Authenticate" not in err.value.headers
    else:
        assert err.value.headers["WWW-Authenticate"] == ", ".join(challenges)


class TestGetter:
    def test_has_async_implementation(self):
        class NoOverride(getter.Getter):
            def load(self, req, *, challenges=None):
                return "foo"

        assert NoOverride.async_calls_sync_load is True

        class Override(getter.Getter):
            def load(self, req, *, challenges=None):
                return "foo"

            def load_async(self, req, *, challenges=None):
                return "bar"

        assert Override.async_calls_sync_load is False

        class Nested(NoOverride):
            def load_async(self, req, *, challenges=None):
                return "bar"

        assert Nested.async_calls_sync_load is False

    @pytest.mark.asyncio
    async def test_default_async(self):
        class Dummy(getter.Getter):
            def load(self, req, *, challenges=None):
                return "foo"

        assert await Dummy().load_async(None) == "foo"


class TestHeaderGetter:
    def test_init(self):
        g = getter.HeaderGetter("foo")

        assert g.header_key == "foo"

    @pytest.mark.asyncio
    async def test_ok(self):
        g = getter.HeaderGetter("foo")
        req = make_request(headers={"foo": "bar"})
        assert g.load(req) == "bar"
        assert await g.load_async(req) == "bar"
        req = make_request(headers={"foo": "bar", "bar": "foo"})
        assert g.load(req) == "bar"
        assert await g.load_async(req) == "bar"

    @pytest.mark.parametrize("challenges", (None, ("foo", "bar")))
    @pytest.mark.asyncio
    async def test_error(self, patch_exception_str, challenges):
        g = getter.HeaderGetter("bar")

        req = make_request(headers={"foo": "bar"})
        await check_challenges(g, req, BackendNotApplicable, "Missing bar header", challenges)
        req = make_request()
        await check_challenges(g, req, BackendNotApplicable, "Missing bar header", challenges)


class TestAuthHeaderGetter:
    def test_init(self):
        g = getter.AuthHeaderGetter("foo")

        assert g.auth_header_type == "foo"
        assert g.header_key == "Authorization"

        g = getter.AuthHeaderGetter("FOO")
        assert g.auth_header_type == "foo"

    @pytest.mark.asyncio
    async def test_ok(self):
        g = getter.AuthHeaderGetter("foo")
        req = make_request(headers={"Authorization": "foo bar"})
        assert g.load(req) == "bar"
        assert await g.load_async(req) == "bar"

        g = getter.AuthHeaderGetter("bar", header_key="foo")
        req = make_request(headers={"foo": "bar baz", "bar": "foo"})
        assert g.load(req) == "baz"
        assert await g.load_async(req) == "baz"

    @pytest.mark.parametrize("challenges", (None, ("foo", "bar")))
    @pytest.mark.asyncio
    async def test_error(self, patch_exception_str, challenges):
        g = getter.AuthHeaderGetter("bar")

        req = make_request(headers={"Auth": "bar"})
        await check_challenges(
            g, req, BackendNotApplicable, "Missing Authorization header", challenges
        )
        req = make_request()
        await check_challenges(
            g, req, BackendNotApplicable, "Missing Authorization header", challenges
        )
        req = make_request(headers={"Authorization": "foo bar"})
        await check_challenges(g, req, BackendNotApplicable, "Must start with", challenges)
        req = make_request(headers={"Authorization": "bar"})
        await check_challenges(g, req, BackendNotApplicable, "Value Missing", challenges)
        req = make_request(headers={"Authorization": "bar baz foo"})
        await check_challenges(g, req, BackendNotApplicable, "Contains extra content", challenges)


class TestParamGetter:
    def test_init(self):
        g = getter.ParamGetter("foo")

        assert g.param_name == "foo"

    @pytest.mark.asyncio
    async def test_ok(self):
        g = getter.ParamGetter("foo")
        req = make_request(query_string="foo=bar")
        assert g.load(req) == "bar"
        assert await g.load_async(req) == "bar"
        req = make_request(query_string="foo=bar&bar=foo")
        assert g.load(req) == "bar"
        assert await g.load_async(req) == "bar"

    @pytest.mark.asyncio
    async def test_form_url_encoded(self, patch_exception_str):
        opt = RequestOptions()
        opt.auto_parse_form_urlencoded = True
        env = testing.create_environ(
            method="POST",
            body="foo=bar&baz=foo",
            headers={"content_type": "application/x-www-form-urlencoded"},
        )
        req = Request(env, options=opt)

        g = getter.ParamGetter("foo")
        assert g.load(req) == "bar"
        assert await g.load_async(req) == "bar"
        g = getter.ParamGetter("foobar")
        with pytest.raises(BackendNotApplicable, match="Missing foobar parameter"):
            g.load(req)
        with pytest.raises(BackendNotApplicable, match="Missing foobar parameter"):
            await g.load_async(req)

    @pytest.mark.parametrize("challenges", (None, ("foo", "bar")))
    @pytest.mark.asyncio
    async def test_error(self, patch_exception_str, challenges):
        g = getter.ParamGetter("bar")

        req = make_request(query_string="foo=bar")
        await check_challenges(g, req, BackendNotApplicable, "Missing bar parameter", challenges)
        req = make_request()
        await check_challenges(g, req, BackendNotApplicable, "Missing bar parameter", challenges)
        req = make_request(query_string="bar=foo&bar=foobar")
        await check_challenges(g, req, BackendNotApplicable, "Multiple value passed", challenges)


class TestCookieGetter:
    def test_init(self):
        g = getter.CookieGetter("foo")

        assert g.cookie_name == "foo"

    @pytest.mark.asyncio
    async def test_ok(self):
        g = getter.CookieGetter("foo")
        req = make_request(headers={"Cookie": "foo=bar"})
        assert g.load(req) == "bar"
        assert await g.load_async(req) == "bar"
        req = make_request(headers={"Cookie": "foo=bar;bar=foo"})
        assert g.load(req) == "bar"
        assert await g.load_async(req) == "bar"

    @pytest.mark.parametrize("challenges", (None, ("foo", "bar")))
    @pytest.mark.asyncio
    async def test_error(self, patch_exception_str, challenges):
        g = getter.CookieGetter("bar")

        req = make_request(headers={"Cookie": "foo=bar"})
        await check_challenges(g, req, BackendNotApplicable, "Missing bar cookie", challenges)
        req = make_request()
        await check_challenges(g, req, BackendNotApplicable, "Missing bar cookie", challenges)
        req = make_request(headers={"Cookie": "bar=foo;bar=foobar"})
        await check_challenges(g, req, BackendNotApplicable, "Multiple value passed", challenges)


class ImplAsync(getter.Getter):
    def load(self, req, *, challenges=None):
        return req.get_param("sync")

    async def load_async(self, req, *, challenges=None):
        return req.get_param("async")


class TestMultiGetter:
    def test_init(self):
        g1 = getter.ParamGetter("foo")
        g2 = getter.CookieGetter("bar")
        g = getter.MultiGetter([g1, g2])

        assert g.getters == (g1, g2)

        assert getter.MultiGetter.async_calls_sync_load is True

    def test_init_error(self):
        with pytest.raises(ValueError, match="Must pass more than one getter"):
            getter.MultiGetter([])
        with pytest.raises(ValueError, match="Must pass more than one getter"):
            getter.MultiGetter([getter.CookieGetter("foo")])
        with pytest.raises(TypeError, match="All getter must inherit from Getter"):
            getter.MultiGetter([getter.CookieGetter("foo"), "foo"])

    @pytest.mark.asyncio
    async def test_ok(self):
        g1 = getter.ParamGetter("foo")
        g2 = getter.CookieGetter("bar")
        g = getter.MultiGetter([g1, g2])

        req = make_request(query_string="foo=bar")
        assert g.load(req) == "bar"
        assert await g.load_async(req) == "bar"
        req = make_request(headers={"Cookie": "bar=foo"})
        assert g.load(req) == "foo"
        assert await g.load_async(req) == "foo"
        req = make_request(query_string="foo=bar", headers={"Cookie": "bar=foo"})
        assert g.load(req) == "bar"
        assert await g.load_async(req) == "bar"
        g = getter.MultiGetter([g2, g1])
        assert g.load(req) == "foo"
        assert await g.load_async(req) == "foo"

    @pytest.mark.asyncio
    async def test_custom_async(self, falcon3):
        g1 = getter.ParamGetter("skip")
        g2 = ImplAsync()

        g = getter.MultiGetter([g1, g2])

        req = make_request(query_string="sync=sync&async=async")
        assert g.load(req) == "sync"
        assert await g.load_async(req) == "sync"

        areq = testing.create_asgi_req(query_string="sync=sync&async=async")
        assert await greenlet_spawn(g.load, areq) == "async"
        # test normal call async call
        assert await g.load_async(areq) == "async"

        # test normal in greenlet_spawn
        def go():
            return await_(g.load_async(areq))

        assert await greenlet_spawn(go) == "async"

    @pytest.mark.parametrize("ch", (None, ("foo", "bar")))
    @pytest.mark.asyncio
    async def test_error(self, patch_exception_str, ch):
        g1 = getter.ParamGetter("foo")
        g2 = getter.CookieGetter("bar")
        g = getter.MultiGetter([g1, g2])

        req = make_request()
        await check_challenges(
            g, req, BackendNotApplicable, "No authentication information found", ch
        )
        req = make_request(query_string="bar=foo")
        await check_challenges(
            g, req, BackendNotApplicable, "No authentication information found", ch
        )
        req = make_request(headers={"Cookie": "foo=bar"})
        await check_challenges(
            g, req, BackendNotApplicable, "No authentication information found", ch
        )
        req = make_request(query_string="bar=foo", headers={"Cookie": "foo=bar"})
        await check_challenges(
            g, req, BackendNotApplicable, "No authentication information found", ch
        )
