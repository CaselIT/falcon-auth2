from typing import Any
from typing import NamedTuple

from falcon import Request
from falcon import Response


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
    is_async: bool
    "Indicates that authenticate is running in async mode."
