from typing import Callable
from typing import Iterable
from typing import List
from typing import Optional

from falcon import HTTPUnauthorized

from .base import AuthBackend
from ..exc import BackendNotApplicable
from ..utils import call_maybe_async
from ..utils import check_backend
from ..utils import RequestAttributes


class CallBackBackend(AuthBackend):
    """Meta-Backend used to notify when another backend has success and/or fails to authenticate
    a request.

    This backend delegates all the authentication actions to the provided ``backend``.

    Args:
        backend (AuthBackend): The backend that will be used to authenticate the requests.
    Keyword Args:
        on_success (Optional[Callable], optional): Callable object that will be invoked with the
            :class:`~.RequestAttributes`, the ``backend`` and the authentication result (the dict
            that will be placed in the request context by the middleware) after a successful
            request authentication. When using falcon in async mode (asgi), this function may
            also be async. Defaults to ``None``.

            Note:
                An error will be raised if an async function is used when using falcon in sync
                mode (wsgi).
        on_failure (Optional[Callable], optional): Callable object that will be invoked with the
            :class:`~.RequestAttributes`, the ``backend`` and the raised exception after a failed
            request authentication. When using falcon in async mode (asgi), this function may
            also be async. Defaults to ``None``.

            Note:
                An error will be raised if an async function is used when using falcon in sync
                mode (wsgi).

            Note:
                This method cannot be used to suppress an exception raised by the ``backend``
                because it will be propagated after ``on_failure`` invocation ends.
                The callable may choose to raise a different exception instead.
    """

    def __init__(
        self,
        backend: AuthBackend,
        *,
        on_success: Optional[Callable] = None,
        on_failure: Optional[Callable] = None,
    ):
        check_backend(backend)
        if on_success and not callable(on_success):
            raise TypeError(f"Expected on_success {on_success} to be a callable object")
        if on_failure and not callable(on_failure):
            raise TypeError(f"Expected on_failure {on_failure} to be a callable object")

        self.backend = backend
        self.on_success = on_success
        self.on_success_is_async = None
        self.on_failure = on_failure
        self.on_failure_is_async = None

    def authenticate(self, attributes: RequestAttributes) -> dict:
        "Authenticates the request and returns the authenticated user."
        try:
            results = self.backend.authenticate(attributes)
            results.setdefault("backend", self.backend)
            if self.on_success:
                _, self.on_success_is_async = call_maybe_async(
                    attributes[4],
                    self.on_success_is_async,
                    "on success",
                    self.on_success,
                    attributes,
                    self.backend,
                    results,
                )
            return results
        except Exception as e:
            if self.on_failure:
                _, self.on_failure_is_async = call_maybe_async(
                    attributes[4],
                    self.on_failure_is_async,
                    "on failure",
                    self.on_failure,
                    attributes,
                    self.backend,
                    e,
                )
            raise


class MultiAuthBackend(AuthBackend):
    """Meta-Backend used to combine multiple authentication backends.

    This backend successfully authenticates a request if one of the provided backends can
    authenticate the request or raises :class:`~.BackendNotApplicable` if no backend can
    authenticate it.

    This backend delegates all the authentication actions to the provided ``backends``.

    Args:
        backends (Iterable[AuthBackend]): The backends to use. They will be used in order.
    Keyword Args:
        continue_on (Callable): A callable object that is called when a backend raises an exception.
            It should return ``True`` if processing should continue to the next backend or
            ``False`` if it should stop by re-raising the backend exception.
            The callable takes the backend and the raised exception as parameters.
            The default implementation continues processing if any backend raises a
            :class:`~.BackendNotApplicable` exception.

            Note:
                This callable is only invoked if a backend raises an instance of
                ``HTTPUnauthorized`` or one of it's subclasses. All other exception types
                are propagated.
    """

    def __init__(self, backends: Iterable[AuthBackend], *, continue_on: Optional[Callable] = None):
        self.backends = tuple(backends)
        if len(self.backends) < 2:
            raise ValueError("Must pass more than two backend")
        if any(not isinstance(b, AuthBackend) for b in self.backends):
            raise TypeError("All backends must inherit from `AuthBackend`")
        if continue_on and not callable(continue_on):
            raise TypeError(f"Expected {continue_on} to be a callable object")

        self.continue_on = continue_on or self._default_continue

    def authenticate(self, attributes: RequestAttributes):
        "Authenticates the request and returns the authenticated user."
        challenges = []

        for backend in self.backends:
            try:
                result = backend.authenticate(attributes)
                result.setdefault("backend", backend)
                return result
            except HTTPUnauthorized as exc:
                if self.continue_on(backend, exc):
                    self._append_challenges(challenges, exc)
                else:
                    raise

        raise BackendNotApplicable(
            description="Cannot authenticate the request", challenges=challenges
        )

    @staticmethod
    def _default_continue(backend: AuthBackend, exc: Exception):
        return isinstance(exc, BackendNotApplicable)

    @staticmethod
    def _append_challenges(challenges: List[str], err: HTTPUnauthorized):
        if err.headers:
            headers = err.headers if isinstance(err.headers, dict) else dict(err.headers)
            www_authenticate = headers.get("WWW-Authenticate")
            if www_authenticate:
                challenges.append(www_authenticate)
