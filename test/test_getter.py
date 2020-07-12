import pytest
from falcon import Request, RequestOptions, testing

from falcon_auth2 import BackendNotApplicable, getter


def make_request(**kw):
    return Request(testing.create_environ(**kw))


def check_challenges(getter, req, err, match, challenges):
    with pytest.raises(BackendNotApplicable, match=match) as err:
        getter.load(req, challenges=challenges)
    if not challenges:
        assert err.value.headers is None or "WWW-Authenticate" not in err.value.headers
    else:
        assert err.value.headers["WWW-Authenticate"] == ", ".join(challenges)


class TestHeaderGetter:
    def test_init(self):
        g = getter.HeaderGetter("foo")

        assert g.header_key == "foo"

    def test_ok(self):
        g = getter.HeaderGetter("foo")
        req = make_request(headers={"foo": "bar"})
        assert g.load(req) == "bar"
        req = make_request(headers={"foo": "bar", "bar": "foo"})
        assert g.load(req) == "bar"

    @pytest.mark.parametrize("challenges", (None, ("foo", "bar")))
    def test_error(self, patch_exception_str, challenges):
        g = getter.HeaderGetter("bar")

        req = make_request(headers={"foo": "bar"})
        check_challenges(g, req, BackendNotApplicable, "Missing bar header", challenges)
        req = make_request()
        check_challenges(g, req, BackendNotApplicable, "Missing bar header", challenges)


class TestAuthHeaderGetter:
    def test_init(self):
        g = getter.AuthHeaderGetter("foo")

        assert g.auth_header_type == "foo"
        assert g.header_key == "Authorization"

        g = getter.AuthHeaderGetter("FOO")
        assert g.auth_header_type == "foo"

    def test_ok(self):
        g = getter.AuthHeaderGetter("foo")
        req = make_request(headers={"Authorization": "foo bar"})
        assert g.load(req) == "bar"

        g = getter.AuthHeaderGetter("bar", header_key="foo")
        req = make_request(headers={"foo": "bar baz", "bar": "foo"})
        assert g.load(req) == "baz"

    @pytest.mark.parametrize("challenges", (None, ("foo", "bar")))
    def test_error(self, patch_exception_str, challenges):
        g = getter.AuthHeaderGetter("bar")

        req = make_request(headers={"Auth": "bar"})
        check_challenges(g, req, BackendNotApplicable, "Missing Authorization header", challenges)
        req = make_request()
        check_challenges(g, req, BackendNotApplicable, "Missing Authorization header", challenges)
        req = make_request(headers={"Authorization": "foo bar"})
        check_challenges(g, req, BackendNotApplicable, "Must start with", challenges)
        req = make_request(headers={"Authorization": "bar"})
        check_challenges(g, req, BackendNotApplicable, "Value Missing", challenges)
        req = make_request(headers={"Authorization": "bar baz foo"})
        check_challenges(g, req, BackendNotApplicable, "Contains extra content", challenges)


class TestParamGetter:
    def test_init(self):
        g = getter.ParamGetter("foo")

        assert g.param_name == "foo"

    def test_ok(self):
        g = getter.ParamGetter("foo")
        req = make_request(query_string="foo=bar")
        assert g.load(req) == "bar"
        req = make_request(query_string="foo=bar&bar=foo")
        assert g.load(req) == "bar"

    def test_form_url_encoded(self, patch_exception_str):
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
        g = getter.ParamGetter("foobar")
        with pytest.raises(BackendNotApplicable, match="Missing foobar parameter"):
            g.load(req)

    @pytest.mark.parametrize("challenges", (None, ("foo", "bar")))
    def test_error(self, patch_exception_str, challenges):
        g = getter.ParamGetter("bar")

        req = make_request(query_string="foo=bar")
        check_challenges(g, req, BackendNotApplicable, "Missing bar parameter", challenges)
        req = make_request()
        check_challenges(g, req, BackendNotApplicable, "Missing bar parameter", challenges)
        req = make_request(query_string="bar=foo&bar=foobar")
        check_challenges(g, req, BackendNotApplicable, "Multiple value passed", challenges)


class TestCookieGetter:
    def test_init(self):
        g = getter.CookieGetter("foo")

        assert g.cookie_name == "foo"

    def test_ok(self):
        g = getter.CookieGetter("foo")
        req = make_request(headers={"Cookie": "foo=bar"})
        assert g.load(req) == "bar"
        req = make_request(headers={"Cookie": "foo=bar;bar=foo"})
        assert g.load(req) == "bar"

    @pytest.mark.parametrize("challenges", (None, ("foo", "bar")))
    def test_error(self, patch_exception_str, challenges):
        g = getter.CookieGetter("bar")

        req = make_request(headers={"Cookie": "foo=bar"})
        check_challenges(g, req, BackendNotApplicable, "Missing bar cookie", challenges)
        req = make_request()
        check_challenges(g, req, BackendNotApplicable, "Missing bar cookie", challenges)
        req = make_request(headers={"Cookie": "bar=foo;bar=foobar"})
        check_challenges(g, req, BackendNotApplicable, "Multiple value passed", challenges)


class TestMultiGetter:
    def test_init(self):
        g1 = getter.ParamGetter("foo")
        g2 = getter.CookieGetter("bar")
        g = getter.MultiGetter([g1, g2])

        assert g.getters == (g1, g2)

    def test_init_error(self):
        with pytest.raises(ValueError, match="Must pass more than one getter"):
            getter.MultiGetter([])
        with pytest.raises(ValueError, match="Must pass more than one getter"):
            getter.MultiGetter([getter.CookieGetter("foo")])
        with pytest.raises(TypeError, match="All getter must inherit from Getter"):
            getter.MultiGetter([getter.CookieGetter("foo"), "foo"])

    def test_ok(self):
        g1 = getter.ParamGetter("foo")
        g2 = getter.CookieGetter("bar")
        g = getter.MultiGetter([g1, g2])

        req = make_request(query_string="foo=bar")
        assert g.load(req) == "bar"
        req = make_request(headers={"Cookie": "bar=foo"})
        assert g.load(req) == "foo"
        req = make_request(query_string="foo=bar", headers={"Cookie": "bar=foo"})
        assert g.load(req) == "bar"
        g = getter.MultiGetter([g2, g1])
        assert g.load(req) == "foo"

    @pytest.mark.parametrize("ch", (None, ("foo", "bar")))
    def test_error(self, patch_exception_str, ch):
        g1 = getter.ParamGetter("foo")
        g2 = getter.CookieGetter("bar")
        g = getter.MultiGetter([g1, g2])

        req = make_request()
        check_challenges(g, req, BackendNotApplicable, "No authentication information found", ch)
        req = make_request(query_string="bar=foo")
        check_challenges(g, req, BackendNotApplicable, "No authentication information found", ch)
        req = make_request(headers={"Cookie": "foo=bar"})
        check_challenges(g, req, BackendNotApplicable, "No authentication information found", ch)
        req = make_request(query_string="bar=foo", headers={"Cookie": "foo=bar"})
        check_challenges(g, req, BackendNotApplicable, "No authentication information found", ch)
