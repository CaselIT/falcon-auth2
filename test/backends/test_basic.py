import base64

import falcon
import pytest

from falcon_auth2 import AuthHeaderGetter
from falcon_auth2 import ParamGetter
from falcon_auth2 import RequestAttributes
from falcon_auth2.backends import BasicAuthBackend
from .conftest import ConfigurableGetter
from .conftest import ResourceFixture


def basic_auth_token(user, pwd, prefix="Basic"):
    token = f"{user}:{pwd}".encode()

    token_b64 = base64.b64encode(token).decode()
    return f"{prefix} {token_b64}" if prefix else token_b64


def find_user(user_dict):
    def m(attr, user, pwd):
        assert isinstance(attr, RequestAttributes)
        for u in user_dict.values():
            if u.user == user and u.pwd == pwd:
                return u
        return None

    return m


class TestBasicAuth(ResourceFixture):
    def test_init(self):
        bab = BasicAuthBackend(find_user)
        assert bab.user_loader == find_user
        assert bab.challenges == ("Basic",)
        assert bab.auth_header_type == "Basic"
        assert isinstance(bab.getter, AuthHeaderGetter)
        assert bab.getter.header_key == "Authorization"
        assert bab.getter.auth_header_type == "basic"

        bab = BasicAuthBackend(find_user, auth_header_type="CustomType")
        assert bab.user_loader == find_user
        assert bab.challenges == ("CustomType",)
        assert bab.auth_header_type == "CustomType"
        assert isinstance(bab.getter, AuthHeaderGetter)
        assert bab.getter.header_key == "Authorization"
        assert bab.getter.auth_header_type == "customtype"

        g = ParamGetter("bar")
        bab = BasicAuthBackend(find_user, auth_header_type="foobar", getter=g)
        assert bab.user_loader == find_user
        assert bab.getter is g
        assert bab.challenges == ("foobar",)

    def test_init_raises(self):
        with pytest.raises(TypeError, match="to be a callable object"):
            BasicAuthBackend(123)
        with pytest.raises(TypeError, match="Expected a subclass of Getter"):
            BasicAuthBackend(find_user, getter=123)

    @pytest.fixture
    def backend(self, user_dict):
        return BasicAuthBackend(find_user(user_dict))

    def test_user(self, user_dict, client, resource):
        user = user_dict["2"]
        req = client.simulate_post(
            "/auth", headers={"Authorization": basic_auth_token(user.user, user.pwd)}
        )
        assert req.text == str(user)
        assert req.status == falcon.HTTP_OK
        assert resource.context.keys() == {"user", "backend"}

    def test_other_getter(self, user_dict, client, backend):
        user = user_dict["3"]
        backend.getter = ParamGetter("auth")
        req = client.simulate_post(
            "/auth", query_string=f"auth={basic_auth_token(user.user, user.pwd, None)}"
        )
        assert req.text == str(user)
        assert req.status == falcon.HTTP_OK

    def test_header_not_found(self, backend, client):
        req = client.simulate_post("/auth")
        assert req.status == falcon.HTTP_UNAUTHORIZED
        assert "Missing Authorization header" in req.text
        assert req.headers.get("WWW-Authenticate") == "Basic"

    class TestBasicAuthOtherType:
        @pytest.fixture
        def backend(self, user_dict):
            return BasicAuthBackend(find_user(user_dict), auth_header_type="CustomType")

        def test_ok(self, user_dict, client):
            user = user_dict["2"]
            req = client.simulate_post(
                "/auth",
                headers={"Authorization": basic_auth_token(user.user, user.pwd, "CustomType")},
            )
            assert req.text == str(user)
            assert req.status == falcon.HTTP_OK

        def test_header_not_found(self, backend, client):
            req = client.simulate_post("/auth")
            assert req.status == falcon.HTTP_UNAUTHORIZED
            assert "Missing Authorization header" in req.text
            assert req.headers.get("WWW-Authenticate") == "CustomType"

    @pytest.mark.parametrize(
        "token, message",
        (
            ("-", "Must start with"),
            (basic_auth_token("foo", "bar", "Foo"), "Must start with"),
            (basic_auth_token("foo", "bar"), "User not found"),
            ("Basic", "Value Missing"),
            ("Basic 123 333", "Contains extra"),
            ("Basic ~~:@@", "Unable to decode credentials"),
            (f"Basic {base64.b64encode(b'no-colon').decode()}", "Unable to decode credentials"),
            (f"Basic {base64.b64encode(b'more:than:two:colon').decode()}", "User not found"),
        ),
    )
    def test_auth_error(self, backend, client, token, message):
        req = client.simulate_post("/auth", headers={"Authorization": token})
        assert req.status == falcon.HTTP_UNAUTHORIZED
        assert message in req.text

        backend.challenges = ("bar",)
        req = client.simulate_get("/auth", headers={"Authorization": token})
        assert req.status == falcon.HTTP_UNAUTHORIZED
        assert req.headers.get("WWW-Authenticate") == "bar"

    def test_async_loader(self, client, backend, asgi):
        async def async_loader(a, u, p):
            return None

        backend.user_loader = async_loader

        for _ in range(3):
            res = client.simulate_get(
                "/auth", headers={"Authorization": basic_auth_token("a", "b")}
            )
            if asgi:
                assert res.status == falcon.HTTP_UNAUTHORIZED
            else:
                assert res.status == falcon.HTTP_INTERNAL_SERVER_ERROR
                assert "Cannot use async user loader" in res.json["description"]

    def test_async_getter(self, client, backend, asgi, user_dict):
        backend.getter = ConfigurableGetter(
            basic_auth_token(user_dict["2"].user, user_dict["2"].pwd).partition(" ")[-1],
            basic_auth_token(user_dict["3"].user, user_dict["3"].pwd).partition(" ")[-1],
            False,
        )

        req = client.simulate_post("/auth", headers={"Authorization": basic_auth_token("a", "b")})
        assert req.status == falcon.HTTP_OK
        if asgi:
            assert req.text == str(user_dict["3"])
        else:
            assert req.text == str(user_dict["2"])

    def test_async_getter_call_sync(self, client, backend, asgi, user_dict):
        backend.getter = ConfigurableGetter(
            basic_auth_token(user_dict["2"].user, user_dict["2"].pwd).partition(" ")[-1],
            basic_auth_token(user_dict["3"].user, user_dict["3"].pwd).partition(" ")[-1],
            True,
        )

        req = client.simulate_post("/auth", headers={"Authorization": basic_auth_token("a", "b")})
        assert req.status == falcon.HTTP_OK
        assert req.text == str(user_dict["2"])
