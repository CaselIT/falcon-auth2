import falcon
import pytest

from falcon_auth2 import exc
from falcon_auth2.utils.compat import falcon2


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


def create_app(auth_middleware, resource, asgi):

    if asgi:
        from falcon.asgi import App

        async def handle(req, resp, ex, params):
            raise falcon.HTTPInternalServerError(description=str(ex))

        app = App(middleware=[auth_middleware])
    else:
        if falcon2:
            from falcon import API as App
        else:
            from falcon import App

        def handle(req, resp, ex, params):
            if isinstance(ex, falcon.HTTPError):
                raise ex
            raise falcon.HTTPInternalServerError(description=str(ex))

        app = App(middleware=[auth_middleware])

    app.add_route("/auth", resource)
    app.add_route("/posts/{post_id}", resource)

    app.add_error_handler(Exception, handle)
    return app


@pytest.fixture
def falcon3():
    if falcon2:
        pytest.skip("Requires async support added in falcon 3")
