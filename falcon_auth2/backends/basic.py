import base64
from typing import Callable, Optional

from falcon import Request

from ..exc import BackendNotApplicable
from ..getter import AuthHeaderGetter, Getter
from ..utils import RequestAttributes, check_getter
from .base import BaseAuthBackend


class BasicAuthBackend(BaseAuthBackend):
    """Implements the `'Basic' HTTP Authentication Scheme <https://tools.ietf.org/html/rfc7617>`_.

    Clients should authenticate by passing the credential in the format ``username:password``
    encoded in ``base64`` in the ``Authorization`` HTTP header, prepending it with the
    type specified in the setting ``auth_header_type``.
    For example, the user ``"Aladdin"`` would provide his password, ``"open sesame"``, with the
    header::

        Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==

    Args:
        user_loader (Callable): A callable object that is called with the
            :class:`~RequestAttributes` object and the username and password credentials
            extracted from the request using the provided ``getter``. It should return the user
            identified by the request, or ``None`` if no user could be not found.

            Note:
                Exception raised in this callable are not handled directly, and are surfaced to
                falcon.
    Keyword Args:
        auth_header_type (string, optional): The type of authentication required in the
            ``Authorization`` header. This value is added to the ``challenges`` in case of errors.
            Defaults to ``"Basic"``.

            Note:
                When passing a custom getter this value is only used to generate the ``challenges``,
                since the getter will be used to obtain the credentials to authenticate.
        getter (Optional[Getter]): Getter used to extract the authentication information from the
            request. When using a custom getter, the returned value must be a ``base64`` encoded
            string with the credentials in the format ``username:password``.
            Defaults to :class:`~.AuthHeaderGetter` initialized with the provided
            ``auth_header_type``.
    """

    def __init__(
        self,
        user_loader: Callable,
        *,
        auth_header_type: str = "Basic",
        getter: Optional[Getter] = None,
    ):
        super().__init__(user_loader, challenges=(auth_header_type,))
        if getter:
            check_getter(getter)
        self.auth_header_type = auth_header_type
        self.getter = getter or AuthHeaderGetter(auth_header_type)

    def _extract_credentials(self, req: Request):
        auth_data = self.getter.load(req, challenges=self.challenges)
        try:
            auth_data = base64.b64decode(auth_data).decode("utf-8")
            username, password = auth_data.split(":", 1)
        except Exception:
            raise BackendNotApplicable(
                description="Invalid Authorization Header: Unable to decode credentials",
                challenges=self.challenges,
            )

        return username, password

    def authenticate(self, attributes: RequestAttributes) -> dict:
        "Authenticates the request and returns the authenticated user."
        username, password = self._extract_credentials(attributes[0])
        return {"user": self.load_user(attributes, username, password)}
