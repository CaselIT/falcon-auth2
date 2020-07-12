import pytest
from falcon import testing

from falcon_auth2 import AuthMiddleware

from ..conftest import User, create_app


class AuthResource:
    def on_post(self, req, resp):
        user = req.context.auth["user"]
        self.context = req.context.auth
        resp.body = str(user)

    def on_get(self, req, resp, **kwargs):
        self.context = req.context.auth
        resp.body = "Success"


class ResourceFixture:
    @pytest.fixture
    def resource(self):
        return AuthResource()


@pytest.fixture
def no_user():
    return User(id=-1, user="anonymous", pwd=None)


@pytest.fixture
def user_dict():
    return {str(id): User(id=id, user=f"user{id}", pwd=f"pwd{id}") for id in range(5)}


def create_app_backend(backend_gn, resource):
    return create_app(AuthMiddleware(backend_gn()), resource)


@pytest.fixture
def app(backend, resource):
    return create_app_backend(lambda: backend, resource)


@pytest.fixture
def client(app):
    return testing.TestClient(app)
