from falcon import HTTPUnauthorized

from falcon_auth2.exc import AuthenticationFailure
from falcon_auth2.exc import BackendNotApplicable
from falcon_auth2.exc import UserNotFound


def test_exc():
    assert issubclass(AuthenticationFailure, HTTPUnauthorized)
    assert issubclass(BackendNotApplicable, HTTPUnauthorized)
    assert issubclass(UserNotFound, HTTPUnauthorized)

    assert not issubclass(AuthenticationFailure, (BackendNotApplicable, UserNotFound))
    assert not issubclass(BackendNotApplicable, (AuthenticationFailure, UserNotFound))
    assert not issubclass(UserNotFound, (BackendNotApplicable, AuthenticationFailure))
