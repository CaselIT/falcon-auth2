from falcon import HTTPUnauthorized


class AuthenticationFailure(HTTPUnauthorized):
    """Raised when an authentication backend fails to authenticate a syntactically correct request.

    This will terminate the request with status 401 if no other logic is present.
    """


class BackendNotApplicable(HTTPUnauthorized):
    """Raised when a request is not understood by an authentication backend.
    This may indicate that the request is intended for another backend.

    This will terminate the request with status 401 if no other logic is present.
    """


class UserNotFound(HTTPUnauthorized):
    """Raised when the ``user_loader`` callable of an authentication backend cannot load an user
    with the received payload.
    This may indicate that the request is intended for another backend.

    This will terminate the request with status 401 if no other logic is present.
    """
