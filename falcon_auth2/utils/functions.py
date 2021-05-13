from asyncio import iscoroutine
from typing import Any
from typing import Callable
from typing import Optional
from typing import Tuple

from .asyncio_compat import await_


def check_backend(backend: Any):
    "Test if input is an AuthBackend"
    from ..backends import AuthBackend

    if not isinstance(backend, AuthBackend):
        raise TypeError(
            f"Invalid authentication backend {backend}. Expected a subclass of AuthBackend"
        )


def check_getter(getter: Any):
    "Test if input is a Getter"
    from ..getter import Getter

    if not isinstance(getter, Getter):
        raise TypeError(f"Invalid getter {getter}. Expected a subclass of Getter")


def call_maybe_async(
    support_async: bool,
    function_is_async: Optional[bool],
    err_msg: str,
    function: Callable,
    *args,
    **kwargs,
) -> Tuple[Any, bool]:
    """Calls a function and waits for the result if it is async.

    Args:
        support_async (bool): Can run async cuntions.
        function_is_async (Optional[bool]): If the function is async. This function will determine
            if ``function`` is async when this parameter is ``None``.
        err_msg (str): Name of the function. Used in case of error.
        function (Callable): The function to call.
        \\*args: Positional arguments to pass to the ``function`` callable.
        \\*\\*kwargs: Keyword arguments to pass to the ``function`` callable.

    Raises:
        TypeError: if ``function`` is async and ``support_async=False``.

    Returns:
        Tuple[Any, bool]: Returns the result and whatever the function is async.
    """
    result = function(*args, **kwargs)
    if function_is_async is None:
        function_is_async = iscoroutine(result)

    if function_is_async:
        if support_async:
            # result is a coroutine here. await it
            result = await_(result)
        else:
            raise TypeError(
                f"Cannot use async {err_msg} {function} when"
                " falcon is not running in async mode (asgi)."
            )
    return result, function_is_async
