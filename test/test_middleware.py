import falcon
import pytest
from falcon import testing

from falcon_auth2 import AuthMiddleware, RequestAttributes
from falcon_auth2.backends import AuthBackend, NoAuthBackend

from .conftest import User


class Resource:
    def __init__(self, on_get, **kw):
        self.on_get = on_get
        for k, v in kw.items():
            setattr(self, k, v)


def create_client(res, loader, mkw=None):
    mkw = mkw or {}
    backend = NoAuthBackend(loader)
    mkw.setdefault("backend", backend)
    app = falcon.API(middleware=AuthMiddleware(**mkw))

    app.add_route("/auth", res)
    app.add_route("/auth/{template}", res)
    app.add_route("/other", res)
    client = testing.TestClient(app)
    client.backend = mkw["backend"]
    return client


flag = object()


def auth(user, text="ok", backend=flag):
    def m(req: falcon.Request, res, **kw):
        assert set(req.context.auth.keys()) == {"user", "backend"}
        assert req.context.auth["user"] is user
        if backend is not flag:
            assert req.context.auth["backend"] is backend
        res.body = text

    return m


def no_auth(text):
    def m(req: falcon.Request, res, **kw):
        assert not hasattr(req.context, "auth")
        res.body = text

    return m


class TestAuthMiddleware:
    def test_init(self):
        b = NoAuthBackend(lambda *args: {})
        am = AuthMiddleware(b)

        assert am.backend is b
        assert am.context_attr == "auth"
        assert am.exempt_methods == frozenset({"OPTIONS"})
        assert am.exempt_templates == frozenset()

    def test_init_all(self):
        b = NoAuthBackend(lambda *args: {})
        am = AuthMiddleware(b, ["/foo", "/bar", "/foo"], ["OPTIONS", "GET"], "bar")

        assert am.backend is b
        assert am.context_attr == "bar"
        assert am.exempt_methods == frozenset(["OPTIONS", "GET"])
        assert am.exempt_templates == frozenset(["/foo", "/bar"])

    def test_init_raises(self):
        with pytest.raises(TypeError, match="Invalid authentication backend"):
            AuthMiddleware(12)

        class C:
            def authenticate(self):
                pass

        with pytest.raises(TypeError, match="Invalid authentication backend"):
            AuthMiddleware(C())

    def test_default(self, user):
        def get(req: falcon.Request, res, **kw):
            assert set(req.context.auth.keys()) == {"user", "backend"}
            assert req.context.auth["user"] is user
            assert req.context.auth["backend"] is client.backend

            res.body = "ok"

        client = create_client(Resource(get), lambda auth: user)

        res = client.simulate_get("/auth")
        assert res.status == falcon.HTTP_OK
        assert res.text == "ok"

    def test_disabled_template(self, user):
        client = create_client(
            Resource(no_auth("ok"), on_post=auth(user, "post")),
            lambda auth: user,
            dict(exempt_templates=["/auth", "/auth/{template}"]),
        )

        res = client.simulate_get("/auth")
        assert res.status == falcon.HTTP_OK
        assert res.text == "ok"
        res = client.simulate_get("/auth/42")
        assert res.status == falcon.HTTP_OK
        assert res.text == "ok"
        res = client.simulate_post("/other")
        assert res.status == falcon.HTTP_OK
        assert res.text == "post"

    def test_disabled_method(self, user):
        client = create_client(
            Resource(no_auth("get"), on_post=auth(user, "post")),
            lambda auth: user,
            dict(exempt_methods=["GET"]),
        )

        res = client.simulate_get("/auth")
        assert res.status == falcon.HTTP_OK
        assert res.text == "get"
        res = client.simulate_post("/auth")
        assert res.status == falcon.HTTP_OK
        assert res.text == "post"

    def test_other_attr(self, user):
        def m(req, res):
            assert set(req.context.foobar.keys()) == {"user", "backend"}
            assert req.context.foobar["user"] is user
            res.body = "ok"

        client = create_client(Resource(m), lambda auth: user, dict(context_attr="foobar"),)

        res = client.simulate_get("/auth")
        assert res.status == falcon.HTTP_OK
        assert res.text == "ok"

    def test_authenticate_args(self, user):
        class MyBackend(AuthBackend):
            def authenticate(self, attributes):
                assert isinstance(attributes, RequestAttributes)
                assert isinstance(attributes.req, falcon.Request)
                assert isinstance(attributes.resp, falcon.Response)
                assert attributes.resource is resource
                assert attributes.params == params
                return {"user": user}

        resource = Resource(auth(user))
        client = create_client(resource, lambda auth: user, {"backend": MyBackend()})

        params = {}
        res = client.simulate_get("/auth")
        assert res.status == falcon.HTTP_OK
        assert res.text == "ok"
        params = {"template": "4242"}
        res = client.simulate_get("/auth/4242")
        assert res.status == falcon.HTTP_OK
        assert res.text == "ok"

    def test_backend_not_overridden(self):
        class MyBackend(AuthBackend):
            def authenticate(self, attributes):
                return {"user": 42, "backend": "a-backend-here"}

        def get(req, res):
            assert req.context.auth["user"] == 42
            assert req.context.auth["backend"] == "a-backend-here"
            res.body = "ok"

        client = create_client(Resource(get), lambda auth: 24, {"backend": MyBackend()})

        res = client.simulate_get("/auth")
        assert res.status == falcon.HTTP_OK
        assert res.text == "ok"

    def test_resource_auth_disabled(self, user):
        client = create_client(
            Resource(no_auth("get"), auth={"auth_disabled": True}), lambda auth: user
        )

        res = client.simulate_get("/auth")
        assert res.status == falcon.HTTP_OK
        assert res.text == "get"

    def test_resource_auth_method(self, user):
        client = create_client(
            Resource(no_auth("get"), on_post=auth(user, "post"), auth={"exempt_methods": "GET"}),
            lambda auth: user,
        )

        res = client.simulate_get("/auth")
        assert res.status == falcon.HTTP_OK
        assert res.text == "get"
        res = client.simulate_post("/auth")
        assert res.status == falcon.HTTP_OK
        assert res.text == "post"

    def test_resource_auth_backend(self, user):
        u2 = User(11, "foo", "foo")
        my_backend = NoAuthBackend(lambda auth: u2)
        client = create_client(
            Resource(auth(u2, "get", my_backend), auth={"backend": my_backend}), lambda auth: user,
        )

        res = client.simulate_get("/auth")
        assert res.status == falcon.HTTP_OK
        assert res.text == "get"
