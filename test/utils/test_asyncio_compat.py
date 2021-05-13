# based on sqlalchemy's test/base/test_concurrency_py3k.py
import asyncio

import pytest

from falcon_auth2.utils import await_
from falcon_auth2.utils import greenlet_spawn


async def run1():
    return 1


async def run2():
    return 2


def go(*fns):
    return sum(await_(fn()) for fn in fns)


class TestAsyncioCompat:
    @pytest.mark.asyncio
    async def test_ok(self):

        assert await greenlet_spawn(go, run1, run2) == 3

    @pytest.mark.asyncio
    async def test_async_error(self):
        async def err():
            raise ValueError("an error")

        with pytest.raises(ValueError, match="an error"):
            await greenlet_spawn(go, run1, err)

    @pytest.mark.asyncio
    async def test_sync_error(self):
        def go():
            await_(run1())
            raise ValueError("sync error")

        with pytest.raises(ValueError, match="sync error"):
            await greenlet_spawn(go)

    @pytest.mark.asyncio
    async def test_await_error(self):
        with pytest.raises(RuntimeError, match="Cannot use await_ outside"):
            await_(run1())

        async def inner_await():
            await_(run1())

        def go():
            await_(inner_await())

        with pytest.raises(RuntimeError, match="Cannot use await_ outside"):
            await greenlet_spawn(go)

    @pytest.mark.asyncio
    async def test_contextvars(self):
        try:
            import contextvars
        except ImportError:
            pytest.skip("Cannot import contexvars")

        var = contextvars.ContextVar("var")
        concurrency = 5

        async def async_inner(val):
            assert val == var.get()
            return var.get()

        def inner(val):
            retval = await_(async_inner(val))
            assert val == var.get()
            assert retval == val
            return retval

        async def task(val):
            var.set(val)
            return await greenlet_spawn(inner, val)

        values = {
            await coro for coro in asyncio.as_completed([task(i) for i in range(concurrency)])
        }
        assert values == set(range(concurrency))
