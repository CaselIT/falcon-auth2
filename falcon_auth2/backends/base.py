from abc import ABCMeta, abstractmethod
from typing import Any, Callable, Iterable, Optional

from ..exc import UserNotFound
from ..getter import Getter
from ..utils import RequestAttributes, check_getter


class AuthBackend(metaclass=ABCMeta):
    """Base class that defines the signature of the :meth:`authenticate`.

    Backend must subclass of this class to be used by the application.
    """

    @abstractmethod
    def authenticate(self, attributes: RequestAttributes) -> dict:
        """Authenticates the request and returns the authenticated user.

        A backend should raise an :class:`AuthenticationFailure` exception to indicate that the
        request can be handled by this backend, but the authentication fails.
        It should instead raise :class:`BackendNotApplicable` if the provided request cannot be
        handled by this backend and :class:`UserNotFound` when no user could be loaded with the
        provided credentials.

        Args:
            attributes (RequestAttributes): The current request attributes. It's a named tuple
                which contains the falcon request and response objects, the resource activate
                and the parameter matched in the url.

        Returns:
            dict: A dictionary with a required ``"user"`` key containing the authenticated
                user. This dictionary may optionally contain additional keys specific to this
                backend. If the ``"backend"`` key is specified, the middleware will not override it.
        """


class BaseAuthBackend(AuthBackend):
    """Utility class that handles calling a provided function to load an user from the
    request authentication information in the :meth:`load_user`.

    Args:
        user_loader (Callable): A callable object that is called with the :class:`RequestAttributes`
            object as well as any relevant data extracted from the request by the backend. The
            arguments passed to ``user_loader`` will vary depending on the class:`AuthBackend`.
            It should return the user identified by the request, or ``None`` if no user could be
            not found.

            Note:
                Exception raised in this function are not handled directly, and are surfaced to
                falcon.
    Keyword Args:
        challenges (Optional[Iterable[str]], optional): One or more authentication challenges to
            use as the value of the ``WWW-Authenticate`` header in case of errors.
            Defaults to ``None``.
    """

    def __init__(self, user_loader: Callable, challenges: Optional[Iterable[str]] = None):
        if not callable(user_loader):
            raise TypeError(f"Expected {user_loader} to be a callable object")

        self.user_loader = user_loader
        self.challenges = tuple(challenges) if challenges else None

    def load_user(self, attributes: RequestAttributes, *args, **kwargs) -> Any:
        """Invoke the provided ``user_loader()`` callable to allow the app to retrieve
        the user record. If no such record is found, raises a :class:`UserNotFound`
        exception.

        Args:
            attributes (RequestAttributes): The request attributes.
            *args: Positional arguments to pass to the ``user_loader()`` callable.
            **kwargs: Keyword arguments to pass to the ``user_loader()`` callable.

        Returns:
            Any: The loaded user object.
        """
        user = self.user_loader(attributes, *args, **kwargs)
        if not user:
            raise UserNotFound(
                description="User not found for provided payload", challenges=self.challenges
            )
        return user


class NoAuthBackend(BaseAuthBackend):
    """No authentication backend.

    This backend does not perform any authentication check. It can be used with the
    :class:`MultiAuthBackend` in order to provide a fallback for an unauthenticated user.

    Args:
        user_loader (Callable): A callable object that is called with the :class:`RequestAttributes`
            object and returns a default unauthenticated user.
    Keyword Args:
        challenges (Optional[Iterable[str]], optional): One or more authentication challenges to
            use as the value of the ``WWW-Authenticate`` header in case of errors.
            Defaults to ``None``.
    """

    def authenticate(self, attributes: RequestAttributes) -> dict:
        "Authenticates the request and returns the authenticated user."
        return {"user": self.load_user(attributes)}


class GenericAuthBackend(BaseAuthBackend):
    """Generic authentication backend that uses the provided ``getter`` instance and
    ``user_loader`` callable to retrieves the authentication information from the request
    and authenticate the user.

    Depending on the ``getter`` provided, this backend can be used to authenticate the an user
    using a session cookie or using a parameter as token.

    Args:
        user_loader (Callable): A callable object that is called with the :class:`RequestAttributes`
            object and the information extrected from the request using the provided ``getter``.
            It should return the user identified by the request, or ``None`` if no user could be
            not found.
        getter (Getter): Getter used to extract the authentication information from the request.
            The returned values is passed to the user_loader callable.
    Keyword Args:
        payload_key (Optional[str], optional): It defines a key in the dict returned by the
            :meth:`authentication` method that will contain data obtained from the request by the
            ``getter``. Defaults to ``None``.
        challenges (Optional[Iterable[str]], optional): One or more authentication challenges to
            use as the value of the WWW-Authenticate header in case of errors. Defaults to ``None``
    """

    def __init__(
        self,
        user_loader: Callable,
        getter: Getter,
        payload_key: Optional[str] = None,
        challenges: Optional[Iterable[str]] = None,
    ):
        super().__init__(user_loader, challenges)
        check_getter(getter)
        if payload_key in {"backend", "user"}:
            raise ValueError(f"The payload_key cannot have value {payload_key}")

        self.getter = getter
        self.payload_key = payload_key

    def authenticate(self, attributes: RequestAttributes) -> dict:
        "Authenticates the request and returns the authenticated user."
        auth_data = self.getter.load(attributes[0], self.challenges)
        result = {"user": self.load_user(attributes, auth_data)}
        if self.payload_key is not None:
            result[self.payload_key] = auth_data
        return result
