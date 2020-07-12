from abc import ABCMeta, abstractmethod
from typing import Iterable, Optional

from falcon import Request

from .exc import BackendNotApplicable


class Getter(metaclass=ABCMeta):
    """Base getter class, that defined the interface for the getters."""

    @abstractmethod
    def load(self, req: Request, *, challenges: Optional[Iterable[str]] = None) -> str:
        """Loads the specified attribute from the provided request.

        The ``challenges``, when provided, will be added to ``WWW-Authenticate`` header in case
        of error.

        Args:
            req (Request): The current request.
        Keyword Args:
            challenges (Optional[Iterable[str]], optional): One or more authentication challenges
                to use as the value of the ``WWW-Authenticate`` header in case of errors.

        Returns:
            str: The loaded data, in case of success.
        """


class HeaderGetter(Getter):
    """Gets the specified header from the request.

    Args:
        header_key (str): the name of the header to load.
    """

    def __init__(self, header_key: str):
        self.header_key = header_key

    def load(self, req: Request, *, challenges: Optional[Iterable[str]] = None) -> str:
        """Loads the header from the provided request"""
        header_value = req.get_header(self.header_key)
        if not header_value:
            raise BackendNotApplicable(
                description=f"Missing {self.header_key} header", challenges=challenges
            )
        return header_value


class AuthHeaderGetter(HeaderGetter):
    """Get the auth header from the request, checking that it in the form
    ``<auth_header_type> value``.

    Args:
        auth_header_type (str): The type of the auth header. Common values are ``Basic``,
            ``Bearer``.
    Keyword Args:
        header_key (str, optional): The name of the header to load. Defaults to "Authorization".
    """

    def __init__(self, auth_header_type: str, *, header_key: str = "Authorization"):
        super().__init__(header_key)
        self.auth_header_type = auth_header_type.casefold()

    def load(self, req: Request, *, challenges: Optional[Iterable[str]] = None) -> str:
        """Loads the header from the provided request"""
        prefix, _, value = super().load(req, challenges=challenges).partition(" ")
        if prefix.casefold() != self.auth_header_type:
            raise BackendNotApplicable(
                description=f"Invalid {self.header_key} header: Must "
                f"start with {self.auth_header_type.title()}",
                challenges=challenges,
            )

        if not value:
            raise BackendNotApplicable(
                description="Invalid Authorization header: Value Missing", challenges=challenges
            )

        if " " in value:
            raise BackendNotApplicable(
                description="Invalid Authorization header: Contains extra content",
                challenges=challenges,
            )

        return value


class ParamGetter(Getter):
    """Gets the specified parameter from the request.

    NOTE: If the parameter appears multiple times an error will be raised.

    NOTE: When :py:attr:`falcon.Request.RequestOptions.auto_parse_form_urlencoded` is set to
    ``True``, this getter can also retrieve parameter in the body of a form-urlencoded request.

    Args:
        param_name (str): the name of the param to load.
    """

    def __init__(self, param_name: str):
        self.param_name = param_name

    def load(self, req: Request, *, challenges: Optional[Iterable[str]] = None) -> str:
        """Loads the parameter from the provided request"""
        param_value = req.get_param_as_list(self.param_name)
        if not param_value:
            raise BackendNotApplicable(
                description=f"Missing {self.param_name} parameter", challenges=challenges
            )
        if len(param_value) > 1:
            raise BackendNotApplicable(
                description=f"Invalid {self.param_name} parameter: Multiple value passed",
                challenges=challenges,
            )

        return param_value[0]


class CookieGetter(Getter):
    """Gets the specified cookie from the request.

    NOTE: If the cookie appears multiple times an error will be raised.

    Args:
        cookie_name (str): the name of the cookie to load.
    """

    def __init__(self, cookie_name: str):
        self.cookie_name = cookie_name

    def load(self, req: Request, *, challenges: Optional[Iterable[str]] = None) -> str:
        """Loads the cookie from the provided request"""
        cookie_value = req.get_cookie_values(self.cookie_name)
        if not cookie_value:
            raise BackendNotApplicable(
                description=f"Missing {self.cookie_name} cookie", challenges=challenges
            )
        if len(cookie_value) > 1:
            raise BackendNotApplicable(
                description=f"Invalid {self.cookie_name} cookie: Multiple value passed",
                challenges=challenges,
            )

        return cookie_value[0]


class MultiGetter(Getter):
    """Combines multiple getters. This is useful if a value can be passed in multiple ways
    to the server, like using an header of a query parameter.

    NOTE: The first valid value is returned. Wrong values are ignored and an exception will
    only be raised if no getter can return a valid value.

    Args:
        getter (Iterable[Getter]): The getters to use. They will be tried in order and the first
            matching value is returned.
    """

    def __init__(self, getters: Iterable[Getter]):
        self.getters = tuple(getters)
        if len(self.getters) < 2:
            raise ValueError("Must pass more than one getter")
        if any(not isinstance(g, Getter) for g in self.getters):
            raise TypeError("All getter must inherit from Getter")

    def load(self, req: Request, *, challenges: Optional[Iterable[str]] = None) -> str:
        """Loads the value from the provided request using the provided getters"""
        for p in self.getters:
            try:
                return p.load(req)
            except BackendNotApplicable:
                pass
        raise BackendNotApplicable(
            description="No authentication information found", challenges=challenges
        )
