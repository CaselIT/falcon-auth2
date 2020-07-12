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
from falcon_auth2.compat import falcon2

from .conftest import ResourceFixture, create_app_backend
from .test_basic import find_user

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

        def test_ok(self, backend, no_user, client):
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

    def test_default(self, no_user, backend, resource):
        canary = []

        def on_success(attr, backend, results):
            canary.append(1)
            assert isinstance(results["backend"], CustomBackend)
            assert results["user"] is no_user

        app = create_app_backend(
            lambda: CallBackBackend(backend(), on_success=on_success), resource
        )
        client = testing.TestClient(app)
        # CustomBackend replies
        res = client.simulate_post("/auth")
        assert res.status == falcon.HTTP_OK
        assert res.text == str(no_user)
        assert canary == [1]

    def test_custom_continue(self, no_user, backend, resource):
        canary = []

        # fail on basic auth backend not applicable
        def continue_on(backend, exc):
            assert isinstance(backend, AuthBackend)
            assert isinstance(exc, falcon.HTTPUnauthorized)
            assert backend is multi.backends[len(canary)]
            canary.append(1)
            return len(canary) < 2

        multi = backend(continue_on)
        app = create_app_backend(lambda: multi, resource)
        client = testing.TestClient(app)
        res = client.simulate_post("/auth")
        assert res.status == falcon.HTTP_UNAUTHORIZED

    def test_other_exception(self, backend, resource):
        app = create_app_backend(backend, resource)
        if falcon2:

            def handle(req, resp, ex, params):
                raise falcon.HTTPInternalServerError()

            app.add_error_handler(Exception, handle)

        client = testing.TestClient(app)
        CustomBackend.exc = TypeError("some exception")
        res = client.simulate_post("/auth")
        assert res.status == falcon.HTTP_INTERNAL_SERVER_ERROR

    def test_auth_failure(self, backend, resource):
        # fail with AuthenticationFailure
        app = create_app_backend(backend, resource)
        client = testing.TestClient(app)
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
