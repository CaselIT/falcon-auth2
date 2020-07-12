import falcon
import pytest

from falcon_auth2 import HeaderGetter, ParamGetter, RequestAttributes
from falcon_auth2.backends import GenericAuthBackend, NoAuthBackend

from .conftest import ResourceFixture


def mock_loader(attr):
    return None


class TestNoAuthBackend(ResourceFixture):
    def test_init(self):
        nab = NoAuthBackend(mock_loader)
        assert nab.user_loader == mock_loader
        assert nab.challenges is None

        nab = NoAuthBackend(mock_loader, challenges=["foo", "bar"])
        assert nab.user_loader == mock_loader
        assert nab.challenges == ("foo", "bar")

    def test_init_raises(self):
        with pytest.raises(TypeError, match="to be a callable object"):
            NoAuthBackend(123)

    @pytest.fixture
    def backend(self, no_user):
        def m(attr):
            assert isinstance(attr, RequestAttributes)
            return no_user

        return NoAuthBackend(m)

    def test_user(self, no_user, client):
        req = client.simulate_post("/auth")
        assert req.status == falcon.HTTP_OK
        assert req.text == str(no_user)

    def test_no_user(self, client, backend):
        backend.user_loader = lambda a: None

        req = client.simulate_get("/auth")

        assert req.status == falcon.HTTP_UNAUTHORIZED
        assert "User not found" in req.text
        assert req.headers.get("WWW-Authenticate") is None

        backend.challenges = ("foo",)
        req = client.simulate_get("/auth")
        assert req.status == falcon.HTTP_UNAUTHORIZED
        assert req.headers.get("WWW-Authenticate") == "foo"


class TestGenericAuthBackend(ResourceFixture):
    def test_init(self):
        g = ParamGetter("bar")
        gab = GenericAuthBackend(mock_loader, g)
        assert gab.user_loader == mock_loader
        assert gab.getter is g
        assert gab.challenges is None
        assert gab.payload_key is None

        gab = GenericAuthBackend(mock_loader, g, payload_key="foobar", challenges=list("abc"))
        assert gab.user_loader == mock_loader
        assert gab.getter is g
        assert gab.challenges == tuple("abc")
        assert gab.payload_key == "foobar"

    def test_init_raises(self):
        g = ParamGetter("bar")
        with pytest.raises(TypeError, match="to be a callable object"):
            GenericAuthBackend(123, g)
        with pytest.raises(TypeError, match="Expected a subclass of Getter"):
            GenericAuthBackend(mock_loader, 123)
        for pk in ("backend", "user"):
            with pytest.raises(ValueError, match="The payload_key cannot have"):
                GenericAuthBackend(mock_loader, g, payload_key=pk)

    @pytest.fixture
    def backend(self, user_dict):
        def m(attr, data):
            assert isinstance(attr, RequestAttributes)
            return user_dict.get(data)

        return GenericAuthBackend(m, HeaderGetter("foo"))

    def test_user(self, user_dict, client):
        req = client.simulate_post("/auth", headers={"foo": "3"})
        assert req.status == falcon.HTTP_OK
        assert req.text == str(user_dict["3"])

    def test_other_getter(self, user_dict, client, backend):
        backend.getter = ParamGetter("bar")
        req = client.simulate_post("/auth", query_string="bar=2")
        assert req.status == falcon.HTTP_OK
        assert req.text == str(user_dict["2"])

    def test_header_not_found(self, backend, client):
        req = client.simulate_post("/auth")
        assert req.status == falcon.HTTP_UNAUTHORIZED
        assert "Missing foo header" in req.text
        assert req.headers.get("WWW-Authenticate") is None

        backend.challenges = ("bar",)
        req = client.simulate_get("/auth")
        assert req.status == falcon.HTTP_UNAUTHORIZED
        assert req.headers.get("WWW-Authenticate") == "bar"

    def test_user_not_found(self, backend, client):
        req = client.simulate_post("/auth", headers={"foo": "33"})
        assert req.status == falcon.HTTP_UNAUTHORIZED
        assert "User not found" in req.text

        backend.challenges = ("bar",)
        req = client.simulate_get("/auth", headers={"foo": "33"})
        assert req.status == falcon.HTTP_UNAUTHORIZED
        assert req.headers.get("WWW-Authenticate") == "bar"

    def test_return_key(self, backend, client, resource, user_dict):
        backend.payload_key = "foo_bar"

        req = client.simulate_post("/auth", headers={"foo": "2"})
        assert req.status == falcon.HTTP_OK
        assert req.text == str(user_dict["2"])

        assert resource.context["user"] == user_dict["2"]
        assert resource.context["foo_bar"] == "2"
