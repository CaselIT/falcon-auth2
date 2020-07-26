import pytest

from falcon_auth2.backends import NoAuthBackend
from falcon_auth2.getter import HeaderGetter
from falcon_auth2.utils import RequestAttributes, check_backend, check_getter


def test_requestAttributes():
    ra = RequestAttributes(1, 2, 3, 4, 5)
    assert ra.req == 1
    assert ra.resp == 2
    assert ra.resource == 3
    assert ra.params == 4
    assert ra.is_async == 5


def test_check_backend():
    check_backend(NoAuthBackend(lambda x: None))
    with pytest.raises(TypeError, match="Invalid authentication backend"):
        check_backend(123)


def test_check_getter():
    check_getter(HeaderGetter("foo"))
    with pytest.raises(TypeError, match="Invalid getter"):
        check_getter(123)
