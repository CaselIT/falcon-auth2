from abc import ABCMeta
from abc import abstractmethod
from typing import Any
from typing import Callable
from typing import Iterable
from typing import Optional

from ..exc import UserNotFound
from ..getter import Getter
from ..utils import await_
from ..utils import call_maybe_async
from ..utils import check_getter
from ..utils import RequestAttributes


class AuthBackend(metaclass=ABCMeta):
    """Base class that defines the signature of the :meth:`authenticate` method.

    Backend must subclass of this class to be used by the :class:`~.AuthMiddleware` middleware.
    """

    @abstractmethod
    def authenticate(self, attributes: RequestAttributes) -> dict:
        """Authenticates the request and returns the authenticated user.

        If a request cannot be authenticated a backed should raise:

        * :class:`~.AuthenticationFailure` to indicate that the request can be handled by this
          backend, but the authentication fails.
        * :class:`~.BackendNotApplicable` if the provided request cannot be handled by this backend.
          This is usually raised by the :class:`~.Getter` used by the backend to process the
          request.
        * :class:`~.UserNotFound` when no user could be loaded with the provided credentials.

        Args:
            attributes (RequestAttributes): The current request attributes. It's a named tuple
                which contains the falcon request and response objects, the activated resource
                and the parameters matched in the url.

        Returns:
            dict: A dictionary with a required ``"user"`` key containing the authenticated
            user. This dictionary may optionally contain additional keys specific to this
            backend. If the ``"backend"`` key is specified, the middleware will not override it.
        """


class BaseAuthBackend(AuthBackend, metaclass=ABCMeta):
    """Utility class that handles calling a provided callable to load an user from the
    authentication information of the request in the :meth:`load_user` method.

    Args:
        user_loader (Callable): A callable object that is called with the
            :class:`~.RequestAttributes` object as well as any relevant data extracted from
            the request by the backend. The arguments passed to ``user_loader`` will vary
            depending on the :class:`AuthBackend`. It should return the user identified by
            the request, or ``None`` if no user could be not found.
            When using falcon in async mode (asgi), this function may also be async.

            Note:
                An error will be raised if an async function is used when using falcon in sync
                mode (wsgi).

            Note:
                Exceptions raised in this callable are not handled directly, and are surfaced to
                falcon.
    Keyword Args:
        challenges (Optional[Iterable[str]], optional): One or more authentication challenges to
            use as the value of the ``WWW-Authenticate`` header in case of errors.
            Defaults to ``None``.
    """

    def __init__(self, user_loader: Callable, *, challenges: Optional[Iterable[str]] = None):
        if not callable(user_loader):
            raise TypeError(f"Expected {user_loader} to be a callable object")

        self.user_loader = user_loader
        self.user_loader_is_async = None
        self.challenges = tuple(challenges) if challenges else None

    def load_user(self, attributes: RequestAttributes, *args, **kwargs) -> Any:
        """Invokes the provided ``user_loader`` callable to allow the app to retrieve
        the user record. If no such record is found, raises a :class:`~.UserNotFound`
        exception.

        Args:
            attributes (RequestAttributes): The request attributes.
            \\*args: Positional arguments to pass to the ``user_loader`` callable.
            \\*\\*kwargs: Keyword arguments to pass to the ``user_loader`` callable.

        Returns:
            Any: The loaded user object returned by ``user_loader``.
        """
        is_async = attributes[4]
        user, self.user_loader_is_async = call_maybe_async(
            is_async,
            self.user_loader_is_async,
            "user loader",
            self.user_loader,
            attributes,
            *args,
            **kwargs,
        )
        if not user:
            raise UserNotFound(
                description="User not found for provided payload", challenges=self.challenges
            )
        return user


class NoAuthBackend(BaseAuthBackend):
    """No authentication backend.

    This backend does not perform any authentication check. It can be used with the
    :class:`~.MultiAuthBackend` in order to provide a fallback for an unauthenticated user or to
    implement a complitely custom authentication workflow.

    Args:
        user_loader (Callable): A callable object that is called with the
            :class:`~.RequestAttributes` object and returns a default unauthenticated user (
            alternatively the user identified by a custom authentication workflow) or ``None``
            if no user could be not found.
            When using falcon in async mode (asgi), this function may also be async.

            Note:
                An error will be raised if an async function is used when using falcon in sync
                mode (wsgi).

            Note:
                Exceptions raised in this callable are not handled directly, and are surfaced to
                falcon.
    Keyword Args:
        challenges (Optional[Iterable[str]], optional): One or more authentication challenges to
            use as the value of the ``WWW-Authenticate`` header in case of errors.
            Defaults to ``None``.
    """

    def authenticate(self, attributes: RequestAttributes) -> dict:
        "Authenticates the request and returns the authenticated user."
        return {"user": self.load_user(attributes)}


class GenericAuthBackend(BaseAuthBackend):
    """Generic authentication backend that delegates the verification of the authentication
    information retried from the request by the provided ``getter`` to the ``user_loader``
    callable.

    This backend can be used to quickly implement custom authentication schemes or as an adapter
    to other authentication libraries.

    Depending on the ``getter`` provided, this backend can be used to authenticate the an user
    using a session cookie or using a parameter as token.

    Args:
        user_loader (Callable): A callable object that is called with the
            :class:`~.RequestAttributes` object and the information extracted from the request
            using the provided ``getter``. It should return the user identified by the request,
            or ``None`` if no user could be not found.
            When using falcon in async mode (asgi), this function may also be async.

            Note:
                An error will be raised if an async function is used when using falcon in sync
                mode (wsgi).

            Note:
                Exceptions raised in this callable are not handled directly, and are surfaced to
                falcon.
        getter (Getter): Getter used to extract the authentication information from the request.
            The returned value is passed to the ``user_loader`` callable.
    Keyword Args:
        payload_key (Optional[str], optional): It defines a key in the dict returned by the
            :meth:`authentication` method that will contain data obtained from the request by the
            ``getter``. Use ``None`` to disable this functionality. Defaults to ``None``.
        challenges (Optional[Iterable[str]], optional): One or more authentication challenges to
            use as the value of the ``WWW-Authenticate`` header in case of errors.
            Defaults to ``None``.
    """

    def __init__(
        self,
        user_loader: Callable,
        getter: Getter,
        *,
        payload_key: Optional[str] = None,
        challenges: Optional[Iterable[str]] = None,
    ):
        super().__init__(user_loader, challenges=challenges)
        check_getter(getter)
        if payload_key in {"backend", "user"}:
            raise ValueError(f"The payload_key cannot have value {payload_key}")

        self.getter = getter
        self.payload_key = payload_key

    def authenticate(self, attributes: RequestAttributes) -> dict:
        "Authenticates the request and returns the authenticated user."
        is_async = attributes[4]
        if is_async and not self.getter.async_calls_sync_load:
            auth_data = await_(self.getter.load_async(attributes[0], challenges=self.challenges))
        else:
            auth_data = self.getter.load(attributes[0], challenges=self.challenges)
        result = {"user": self.load_user(attributes, auth_data)}
        if self.payload_key is not None:
            result[self.payload_key] = auth_data
        return result
