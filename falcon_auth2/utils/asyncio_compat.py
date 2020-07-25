import sys

try:
    import greenlet

    # implementation based on snaury gist at
    # https://gist.github.com/snaury/202bf4f22c41ca34e56297bae5f33fef
    # Issue for context: https://github.com/python-greenlet/greenlet/issues/173
    class _AsyncIoGreenlet(greenlet.greenlet):
        def __init__(self, fn, driver):
            greenlet.greenlet.__init__(self, fn, driver)
            self.driver = driver

    def await_(awaitable):
        # this is called in the context greenlet while running __fn
        current = greenlet.getcurrent()
        if not isinstance(current, _AsyncIoGreenlet):
            raise TypeError("Cannot use await_ outside of greenlet_spawn target")
        # returns the control to the driver greenlet passing it
        # a coroutine to run. Once the awaitable is done, the driver greenlet
        # switches back to this greenlet with the result of awaitable that is
        # then returned to the caller (or raised as error)
        return current.driver.switch(awaitable)

    async def greenlet_spawn(__fn, *args, **kw):
        context = _AsyncIoGreenlet(__fn, greenlet.getcurrent())
        # runs the function synchronously in gl greenlet. If the execution
        # is interrupted by await_, context is not dead and result is a
        # coroutine to wait. If the context is dead the function has
        # returned, and its result can be returned.
        try:
            result = context.switch(*args, **kw)
            while not context.dead:
                try:
                    # wait for a coroutine from await_ and then return its result
                    # back to it.
                    value = await result
                except Exception:
                    # this allows an exception to be raised within
                    # the moderated greenlet so that it can continue
                    # its expected flow.
                    result = context.throw(*sys.exc_info())
                else:
                    result = context.switch(value)
        finally:
            # clean up to avoid cycle resolution by gc
            del context.driver
        return result


except ImportError:  # pragma: no cover
    greenlet = None

    def await_(awaitable):
        raise ValueError("Greenlet is required to use this function")

    async def greenlet_spawn(__fn, *args, **kw):
        raise ValueError("Greenlet is required to use this function")
