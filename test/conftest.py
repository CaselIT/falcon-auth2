import falcon
import pytest

from falcon_auth2 import exc


@pytest.fixture
def patch_exception_str(monkeypatch):
    def __str__(self):
        return str(self.to_dict())

    monkeypatch.setattr(exc.BackendNotApplicable, "__str__", __str__)
    monkeypatch.setattr(exc.AuthenticationFailure, "__str__", __str__)
    monkeypatch.setattr(exc.UserNotFound, "__str__", __str__)


class User:
    def __init__(self, id, user, pwd):
        self.id = id
        self.user = user
        self.pwd = pwd

    def __str__(self):
        return f"User(id='{self.id}', user={self.user})"


@pytest.fixture()
def user():
    return User(id=1, user="foo", pwd="bar")


def create_app(auth_middleware, resource):

    api = falcon.API(middleware=[auth_middleware])

    api.add_route("/auth", resource)
    api.add_route("/posts/{post_id}", resource)
    return api
