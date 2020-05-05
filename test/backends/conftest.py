import falcon
import pytest
from falcon import testing

from falcon_auth2 import AuthMiddleware

from ..conftest import User


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


@pytest.fixture(scope="function")
def auth_middleware(backend):
    return AuthMiddleware(backend)


@pytest.fixture
def app(auth_middleware, resource):

    api = falcon.API(middleware=[auth_middleware])

    api.add_route("/auth", resource)
    api.add_route("/posts/{post_id}", resource)
    return api


@pytest.fixture
def client(app):
    return testing.TestClient(app)
