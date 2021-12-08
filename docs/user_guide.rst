User guide
-----------

Install
~~~~~~~

.. code:: shell

    $ pip install falcon-auth2[jwt]

| The above will install `falcon-auth2` and also the dependencies to use the ``JWT`` authentication backend.
| If you plan to use async falcon with ASGI run:

.. code:: shell

    $ pip install falcon-auth2[jwt, async]

Usage
~~~~~

This package provides a falcon middleware to authenticate incoming requests using the selected authentication backend. The middleware allows excluding some routes or method from authentication. After a successful authentication the middleware adds the user identified by the request to the ``request.context``.
When using falcon v3+, the middleware also supports async execution.

See below :ref:`example_wsgi` and :ref:`example_asgi` for complete examples.

.. code:: python

    import falcon
    from falcon_auth2 import AuthMiddleware
    from falcon_auth2.backends import BasicAuthBackend

    def user_loader(attributes, user, password):
        if authenticate(user, password):
            return {"username": user}
        return None

    auth_backend = BasicAuthBackend(user_loader)
    auth_middleware = AuthMiddleware(auth_backend)
    # use falcon.API in falcon 2
    app = falcon.App(middleware=[auth_middleware])

    class HelloResource:
        def on_get(self, req, resp):
            # req.context.auth is of the form:
            #
            #   {
            #       'backend': <instance of the backend that performed the authentication>,
            #       'user': <user object retrieved from the user_loader callable>,
            #       '<backend specific item>': <some extra data that may be added by the backend>,
            #       ...
            #   }
            user = req.context.auth["user"]
            resp.media = {"message": f"Hello {user['username']}"}

    app.add_route('/hello', HelloResource())

Overriding authentication for a resource
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The middleware allows each resource to customize the backend used for authentication or the excluded methods. A resource can also specify that does not need authentication.

.. code:: python

    from falcon_auth2 import HeaderGetter
    from falcon_auth2.backends import GenericAuthBackend

    class OtherResource:
        auth = {
            "backend": GenericAuthBackend(
                user_loader=lambda attr, user_header: user_header, getter=HeaderGetter("User")
            ),
            "exempt_methods": ["GET"],
        }

        def on_get(self, req, resp):
            resp.media = {"type": "No authentication for GET"}

        def on_post(self, req, resp):
            resp.media = {"info": f"User header {req.context.auth['user']}"}

    app.add_route("/other", OtherResource())

    class NoAuthResource:
        auth = {"auth_disabled": True}

        def on_get(self, req, resp):
            resp.media = "No auth in this resource"

        def on_post(self, req, resp):
            resp.media = "No auth in this resource"

    app.add_route("/no-auth", NoAuthResource())

Examples
~~~~~~~~
.. _example_wsgi:

WSGI example
^^^^^^^^^^^^

.. literalinclude:: ../examples/readme_example.py

.. _example_asgi:

ASGI example
^^^^^^^^^^^^

.. literalinclude:: ../examples/readme_example_async.py