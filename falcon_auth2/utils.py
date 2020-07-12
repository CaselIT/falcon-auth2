from typing import Any, NamedTuple

from falcon import Request, Response


class RequestAttributes(NamedTuple):
    """Named tuple that is passed to the backend :meth:`~.AuthBackend.authenticate` when a
    request is performed.
    """

    req: Request
    "The falcon request."
    resp: Response
    "The falcon response."
    resource: Any
    "The falcon responder resource."
    params: dict
    "The parameters of passed in the url."


def check_backend(backend: Any):
    from .backends import AuthBackend

    if not isinstance(backend, AuthBackend):
        raise TypeError(
            f"Invalid authentication backend {backend}. Expected a subclass of AuthBackend"
        )


def check_getter(getter: Any):
    from .getter import Getter

    if not isinstance(getter, Getter):
        raise TypeError(f"Invalid getter {getter}. Expected a subclass of Getter")
