from asyncio import iscoroutinefunction
from typing import Any


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
