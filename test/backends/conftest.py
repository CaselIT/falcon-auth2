import pytest
from falcon import testing

from falcon_auth2 import AuthMiddleware, Getter
from falcon_auth2.utils.compat import falcon2

from ..conftest import User, create_app


class AuthResource:
    def on_post(self, req, resp):
        user = req.context.auth["user"]
        self.context = req.context.auth
        resp.body = str(user)

    def on_get(self, req, resp, **kwargs):
        self.context = req.context.auth
        resp.body = "Success"


class AuthResourceAsync:
    async def on_post(self, req, resp):
        user = req.context.auth["user"]
        self.context = req.context.auth
        resp.body = str(user)

    async def on_get(self, req, resp, **kwargs):
        self.context = req.context.auth
        resp.body = "Success"


class ResourceFixture:
    @pytest.fixture
    def resource(self, asgi):
        return AuthResourceAsync() if asgi else AuthResource()


class ConfigurableGetter(Getter):
    def __init__(self, sync_res, async_res, async_calls_sync_load=None):
        self.sync_res = sync_res
        self.async_res = async_res
        if async_calls_sync_load is not None:
            self.async_calls_sync_load = async_calls_sync_load

    def load(self, req, *, challenges=None):
        return self.sync_res

    async def load_async(self, req, *, challenges=None):
        return self.async_res


@pytest.fixture
def no_user():
    return User(id=-1, user="anonymous", pwd=None)


@pytest.fixture
def user_dict():
    return {str(id): User(id=id, user=f"user{id}", pwd=f"pwd{id}") for id in range(5)}


def create_app_backend(backend_gn, resource, asgi):
    return create_app(AuthMiddleware(backend_gn()), resource, asgi)


@pytest.fixture(params=[True, False], ids=["asgi", "wsgi"])
def asgi(request):
    is_asgi = request.param

    if is_asgi and falcon2:
        pytest.skip("Requires async support added in falcon 3")

    return is_asgi


@pytest.fixture
def app(backend, resource, asgi):
    return create_app_backend(backend if callable(backend) else lambda: backend, resource, asgi)


@pytest.fixture
def client(app):
    return testing.TestClient(app)
