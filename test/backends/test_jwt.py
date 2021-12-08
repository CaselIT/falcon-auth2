from datetime import datetime
from datetime import timedelta

from authlib.jose import JsonWebToken
from authlib.jose import jwt
import falcon
import pytest

from falcon_auth2 import AuthHeaderGetter
from falcon_auth2 import ParamGetter
from falcon_auth2 import RequestAttributes
from falcon_auth2.backends import JWTAuthBackend
from .conftest import ConfigurableGetter
from .conftest import ResourceFixture


def jwt_token(key, payload, header=None, prefix="Bearer"):
    header = header or {"alg": "HS256"}
    token = jwt.encode(header, payload, key)

    return f"{prefix} {token.decode()}" if prefix else token.decode()


def find_user(user_dict):
    def m(attr, payload):
        assert isinstance(attr, RequestAttributes)
        return user_dict.get(payload["sub"])

    return m


class TestJWTAuth(ResourceFixture):
    def test_import_error(self, monkeypatch):
        monkeypatch.setattr("falcon_auth2.backends.jwt.has_authlib", False)
        with pytest.raises(ImportError, match="Authlib is required"):
            JWTAuthBackend(find_user, "key")

    def test_init(self):
        jab = JWTAuthBackend(find_user, "key")
        assert jab.user_loader == find_user
        assert jab.challenges == ("Bearer",)
        assert jab.auth_header_type == "Bearer"
        assert jab.key == "key"
        assert isinstance(jab.getter, AuthHeaderGetter)
        assert jab.getter.header_key == "Authorization"
        assert jab.getter.auth_header_type == "bearer"
        assert isinstance(jab.jwt, JsonWebToken)
        assert jab.claims_options == jab.default_claims()
        assert jab.leeway == 0

        jab = JWTAuthBackend(find_user, "key", auth_header_type="CustomType")
        assert jab.user_loader == find_user
        assert jab.challenges == ("CustomType",)
        assert jab.auth_header_type == "CustomType"
        assert isinstance(jab.getter, AuthHeaderGetter)
        assert jab.getter.header_key == "Authorization"
        assert jab.getter.auth_header_type == "customtype"

        g = ParamGetter("bar")
        jab = JWTAuthBackend(
            find_user,
            b"key",
            auth_header_type="foobar",
            getter=g,
            leeway=42,
            claims_options={"iss": {"essential": True}},
        )
        assert jab.user_loader == find_user
        assert jab.getter is g
        assert jab.challenges == ("foobar",)
        assert jab.claims_options == {"iss": {"essential": True}}
        assert jab.leeway == 42

    def test_init_algorithm(self, monkeypatch):
        call = []

        def mock(alg):
            call.append(alg)

        monkeypatch.setattr("falcon_auth2.backends.jwt.JsonWebToken", mock)
        JWTAuthBackend(find_user, "key")
        assert call == [["HS256"]]
        call.clear()
        JWTAuthBackend(find_user, "key", algorithms="RS512")
        assert call == [["RS512"]]
        call.clear()
        JWTAuthBackend(find_user, "key", algorithms=["RS512", "RS256"])
        assert call == [["RS512", "RS256"]]

    def test_init_raises(self):
        with pytest.raises(TypeError, match="to be a callable object"):
            JWTAuthBackend(123, "key")
        with pytest.raises(TypeError, match="Expected a subclass of Getter"):
            JWTAuthBackend(find_user, "key", getter=123)

    @pytest.fixture
    def key(self):
        return "key"

    @pytest.fixture
    def backend(self, user_dict, key):
        return JWTAuthBackend(
            find_user(user_dict), key, claims_options={"sub": {"essential": True}}
        )

    def test_user(self, user_dict, client, resource, key):
        user = user_dict["2"]
        req = client.simulate_post("/auth", headers={"Authorization": jwt_token(key, {"sub": "2"})})
        assert req.text == str(user)
        assert req.status == falcon.HTTP_OK
        assert resource.context.keys() == {"user", "backend"}

    def test_other_getter(self, user_dict, client, backend, key):
        user = user_dict["3"]
        backend.getter = ParamGetter("auth")
        token = jwt_token(key, {"sub": "3"}, prefix=None)
        req = client.simulate_post("/auth", query_string=f"auth={token}")
        assert req.text == str(user)
        assert req.status == falcon.HTTP_OK

    def test_header_not_found(self, backend, client):
        req = client.simulate_post("/auth")
        assert req.status == falcon.HTTP_UNAUTHORIZED
        assert "Missing Authorization header" in req.text
        assert req.headers.get("WWW-Authenticate") == "Bearer"

    class TestBasicAuthOtherType:
        @pytest.fixture
        def backend(self, user_dict, key):
            return JWTAuthBackend(
                find_user(user_dict),
                key,
                claims_options={"sub": {"essential": True}},
                auth_header_type="CustomType",
            )

        def test_ok(self, user_dict, client, key):
            user = user_dict["2"]
            req = client.simulate_post(
                "/auth",
                headers={"Authorization": jwt_token(key, {"sub": "2"}, prefix="CustomType")},
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
            (lambda key: jwt_token(key, {"sub": "2"}, prefix="Foo"), "Must start with"),
            (lambda key: jwt_token(key, {"sub": "99"}), "User not found"),
            (jwt_token("another-key", {"sub": "1"}), "bad_signature"),
            (lambda key: jwt_token(key, {"iss": "99"}), "missing_claim"),
            ("Bearer", "Value Missing"),
        ),
    )
    def test_auth_error(self, backend, client, token, message, key):
        if callable(token):
            token = token(key)
        req = client.simulate_post("/auth", headers={"Authorization": token})
        assert req.status == falcon.HTTP_UNAUTHORIZED
        assert message in req.text

        backend.challenges = ("bar",)
        req = client.simulate_get("/auth", headers={"Authorization": token})
        assert req.status == falcon.HTTP_UNAUTHORIZED
        assert req.headers.get("WWW-Authenticate") == "bar"

    def test_default_claims_ok(self, backend, client, key, user_dict):
        user = user_dict["1"]
        backend.claims_options = backend.default_claims()
        payload = {
            "iss": "my-iss",
            "sub": "1",
            "aud": "my-aud",
            "exp": datetime.utcnow() + timedelta(seconds=10),
            "nbf": datetime.utcnow(),
            "iat": datetime.utcnow(),
        }
        req = client.simulate_post("/auth", headers={"Authorization": jwt_token(key, payload)})
        assert req.text == str(user)
        assert req.status == falcon.HTTP_OK

    def test_default_claims_err(self, backend, client, key, user_dict):
        backend.claims_options = backend.default_claims()
        for key in ("iss", "sub", "aud", "exp", "nbf", "iat"):
            payload = {
                "iss": "my-iss",
                "sub": "1",
                "aud": "my-aud",
                "exp": datetime.utcnow() + timedelta(seconds=10),
                "nbf": datetime.utcnow(),
                "iat": datetime.utcnow(),
            }
            del payload[key]
            req = client.simulate_post("/auth", headers={"Authorization": jwt_token(key, payload)})
            assert req.status == falcon.HTTP_UNAUTHORIZED

    def test_default_claims_leeway(self, backend, client, key):
        backend.claims_options = backend.default_claims()
        payload = {
            "iss": "my-iss",
            "sub": "1",
            "aud": "my-aud",
            "exp": datetime.utcnow() - timedelta(seconds=10),
            "nbf": datetime.utcnow() - timedelta(seconds=10),
            "iat": datetime.utcnow() - timedelta(seconds=10),
        }
        req = client.simulate_post("/auth", headers={"Authorization": jwt_token(key, payload)})
        assert req.status == falcon.HTTP_UNAUTHORIZED
        backend.leeway = 60
        req = client.simulate_post("/auth", headers={"Authorization": jwt_token(key, payload)})
        assert req.status == falcon.HTTP_OK

    def test_dynamic_key(self, backend, client, key):
        called = False

        def get_key(h, p):
            nonlocal called
            called = True
            assert p == payload
            assert "kid" in h
            return h["kid"]

        backend.key = get_key
        payload = {"sub": "1", "aud": "my-aud"}
        token = jwt_token("key-key", payload, header={"kid": "key-key", "alg": "HS256"})
        req = client.simulate_post("/auth", headers={"Authorization": token})
        assert req.status == falcon.HTTP_OK
        assert called
        token = jwt_token("other-key", payload, header={"kid": "other-key", "alg": "HS256"})
        req = client.simulate_post("/auth", headers={"Authorization": token})
        assert req.status == falcon.HTTP_OK

    def test_async_loader(self, client, backend, asgi, key):
        async def async_loader(a, p):
            return None

        backend.user_loader = async_loader

        for _ in range(3):
            res = client.simulate_get(
                "/auth", headers={"Authorization": jwt_token(key, {"sub": "2"})}
            )
            if asgi:
                assert res.status == falcon.HTTP_UNAUTHORIZED
            else:
                assert res.status == falcon.HTTP_INTERNAL_SERVER_ERROR
                assert "Cannot use async user loader" in res.json["description"]

    def test_async_getter(self, client, backend, asgi, user_dict, key):
        backend.getter = ConfigurableGetter(
            jwt_token(key, {"sub": "2"}, prefix=None),
            jwt_token(key, {"sub": "3"}, prefix=None),
            False,
        )

        req = client.simulate_post("/auth", headers={"Authorization": jwt_token(key, {"sub": 9})})
        assert req.status == falcon.HTTP_OK
        if asgi:
            assert req.text == str(user_dict["3"])
        else:
            assert req.text == str(user_dict["2"])

    def test_async_getter_call_sync(self, client, backend, key, user_dict):
        backend.getter = ConfigurableGetter(
            jwt_token(key, {"sub": "2"}, prefix=None),
            jwt_token(key, {"sub": "2"}, prefix=None),
            True,
        )

        req = client.simulate_post("/auth", headers={"Authorization": jwt_token(key, {"sub": 9})})
        assert req.status == falcon.HTTP_OK
        assert req.text == str(user_dict["2"])
