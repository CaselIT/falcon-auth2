import falcon
import pytest
from falcon import testing

from falcon_auth2 import ParamGetter, RequestAttributes, UserNotFound, exc
from falcon_auth2.backends import (
    AuthBackend,
    BasicAuthBackend,
    CallBackBackend,
    GenericAuthBackend,
    MultiAuthBackend,
    NoAuthBackend,
)

from .conftest import ResourceFixture, create_app_backend
from .test_basic import basic_auth_token, find_user

nab = NoAuthBackend(lambda x: None)


class TestCallBackBackend(ResourceFixture):
    def test_init(self):
        cbb = CallBackBackend(nab)
        assert cbb.backend is nab
        assert cbb.on_failure is None
        assert cbb.on_success is None

        def s(*args):
            pass

        def f(*args):
            pass

        cbb = CallBackBackend(nab, on_success=s, on_failure=f)
        assert cbb.backend is nab
        assert cbb.on_failure is f
        assert cbb.on_success is s

    def test_init_raises(self):
        with pytest.raises(TypeError, match="Expected a subclass of AuthBackend"):
            CallBackBackend(123)
        with pytest.raises(TypeError, match="Expected on_success"):
            CallBackBackend(nab, on_success="foo")
        with pytest.raises(TypeError, match="Expected on_failure"):
            CallBackBackend(nab, on_failure="bar")

    class TestOk:
        @pytest.fixture
        def backend(self, no_user):
            return CallBackBackend(NoAuthBackend(lambda attr: no_user))

        def test_no_function(self, client, no_user):
            res = client.simulate_post("/auth")
            assert res.status == falcon.HTTP_OK
            assert res.text == str(no_user)

        def test_ok(self, backend, no_user, client, resource):
            canary = []

            def success(attr, b, result):
                assert isinstance(attr, RequestAttributes)
                assert b is backend.backend
                assert isinstance(b, NoAuthBackend)
                assert result == {"user": no_user, "backend": b}

                canary.append(1)

            backend.on_success = success
            res = client.simulate_post("/auth")
            assert res.status == falcon.HTTP_OK
            assert res.text == str(no_user)
            assert canary == [1]
            assert isinstance(resource.context["backend"], NoAuthBackend)

        def test_async_success(self, client, backend, asgi):
            canary = []

            async def on_success(a, b, r):
                canary.append(1)
                return None

            backend.on_success = on_success

            for _ in range(3):
                canary.clear()
                res = client.simulate_get("/auth")
                if asgi:
                    assert canary == [1]
                    assert res.status == falcon.HTTP_OK
                else:
                    assert canary == []
                    assert res.status == falcon.HTTP_INTERNAL_SERVER_ERROR
                    assert "Cannot use async on success" in res.json["description"]

    class TestErr:
        @pytest.fixture
        def backend(self):
            return CallBackBackend(NoAuthBackend(lambda attr: None))

        def test_no_function(self, client, no_user):
            res = client.simulate_post("/auth")
            assert res.status == falcon.HTTP_UNAUTHORIZED
            assert "User not found " in res.text

        def test_err(self, backend, no_user, client):
            canary = []

            def error(attr, b, error):
                assert isinstance(attr, RequestAttributes)
                assert b is backend.backend
                assert isinstance(b, NoAuthBackend)
                assert isinstance(error, UserNotFound)

                canary.append(1)

            backend.on_failure = error
            res = client.simulate_post("/auth")
            assert res.status == falcon.HTTP_UNAUTHORIZED
            assert "User not found " in res.text
            assert canary == [1]

        def test_async_success(self, client, backend, asgi):
            canary = []

            async def on_failure(a, b, r):
                canary.append(1)
                return None

            backend.on_failure = on_failure

            for _ in range(3):
                canary.clear()
                res = client.simulate_get("/auth")
                if asgi:
                    assert canary == [1]
                    assert res.status == falcon.HTTP_UNAUTHORIZED
                else:
                    assert canary == []
                    assert res.status == falcon.HTTP_INTERNAL_SERVER_ERROR
                    assert "Cannot use async on failure" in res.json["description"]


class CustomBackend(AuthBackend):
    user = None
    exc = None

    def authenticate(self, attributes):
        if self.exc:
            raise self.exc
        return {"user": self.user}


class TestWithMultiBackendAuth(ResourceFixture):
    def test_init(self):
        bl = [NoAuthBackend(lambda x: None)] * 2
        mab = MultiAuthBackend(bl)
        assert mab.backends == tuple(bl)
        assert callable(mab.continue_on)

    def test_init_raises(self):
        bl = [NoAuthBackend(lambda x: None)] * 2
        with pytest.raises(ValueError, match="Must pass more than two backend"):
            MultiAuthBackend(bl[:-1])
        with pytest.raises(TypeError, match="All backends must inherit from"):
            MultiAuthBackend(bl + [123])
        with pytest.raises(TypeError, match="to be a callable object"):
            MultiAuthBackend(bl, continue_on=123)

    @pytest.fixture
    def backend(self, user_dict, no_user):
        CustomBackend.user = no_user

        return lambda continue_on=None: MultiAuthBackend(
            [
                BasicAuthBackend(find_user(user_dict)),
                GenericAuthBackend(lambda attr, data: user_dict.get(data), ParamGetter("id")),
                CustomBackend(),
            ],
            continue_on=continue_on,
        )

    def test_ok(self, no_user, backend, resource, asgi):
        canary = []

        def on_success(attr, backend, results):
            canary.append(1)
            assert isinstance(results["backend"], CustomBackend)
            assert results["user"] is no_user

        app = create_app_backend(
            lambda: CallBackBackend(backend(), on_success=on_success), resource, asgi
        )
        client = testing.TestClient(app)
        # CustomBackend replies
        res = client.simulate_post("/auth")
        assert res.status == falcon.HTTP_OK
        assert res.text == str(no_user)
        assert canary == [1]
        assert isinstance(resource.context["backend"], CustomBackend)

    def test_ok2(self, user_dict, client, backend, resource, asgi):
        user = user_dict["3"]
        # BasicAuthBackend replies
        res = client.simulate_post(
            "/auth", headers={"Authorization": basic_auth_token(user.user, user.pwd)}
        )
        assert res.status == falcon.HTTP_OK
        assert res.text == str(user)
        assert isinstance(resource.context["backend"], BasicAuthBackend)

    def test_custom_continue(self, no_user, backend, resource, asgi):
        canary = []

        # fail on basic auth backend not applicable
        def continue_on(backend, exc):
            assert isinstance(backend, AuthBackend)
            assert isinstance(exc, falcon.HTTPUnauthorized)
            assert backend is multi.backends[len(canary)]
            canary.append(1)
            return len(canary) < 2

        multi = backend(continue_on)
        app = create_app_backend(lambda: multi, resource, asgi)
        client = testing.TestClient(app)
        res = client.simulate_post("/auth")
        assert res.status == falcon.HTTP_UNAUTHORIZED

    def test_other_exception(self, client, asgi):
        CustomBackend.exc = TypeError("some exception")
        res = client.simulate_post("/auth")
        assert res.status == falcon.HTTP_INTERNAL_SERVER_ERROR

    def test_auth_failure(self, client):
        # fail with AuthenticationFailure
        CustomBackend.exc = exc.AuthenticationFailure(description="CustomBackend")
        res = client.simulate_post("/auth")
        assert res.status == falcon.HTTP_UNAUTHORIZED
        assert "CustomBackend" in res.text

        # continue on BackendNotApplicable, fail because no backend could authenticate
        CustomBackend.exc = exc.BackendNotApplicable(
            description="CustomBackend", headers=[("foo", "bar")]
        )
        res = client.simulate_post("/auth")
        assert res.status == falcon.HTTP_UNAUTHORIZED
        assert "Cannot authenticate the request" in res.text
