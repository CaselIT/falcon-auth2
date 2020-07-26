import pytest

from falcon_auth2.utils import await_, greenlet_spawn


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
