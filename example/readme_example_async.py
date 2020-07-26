import falcon.asgi
from falcon_auth2 import AuthMiddleware, HeaderGetter
from falcon_auth2.backends import BasicAuthBackend, GenericAuthBackend

# To run this application with uvicorn (or any other asgi server)
# uvicorn --port 8080 readme_example_async:app
# You can then use httpie to interact with it. Example
# http :8080/hello -a foo:bar
# http :8080/no-auth
# http POST :8000/generic User:foo


async def authenticate(user, password):
    # Check if the user exists and the password match.
    # This is just for the example
    import random

    return random.choice((True, False))


async def user_loader(attributes, user, password):
    if await authenticate(user, password):
        return {"username": user}
    return None


auth_backend = BasicAuthBackend(user_loader)
auth_middleware = AuthMiddleware(auth_backend)
app = falcon.asgi.App(middleware=[auth_middleware])


class HelloResource:
    async def on_get(self, req, resp):
        # req.context.auth is of the form:
        #
        #   {
        #       'backend': <instance of the backend that performed the authentication>,
        #       'user': <user object retrieved from the user_loader callable>,
        #       '<backend specific item>': <some extra data from the backend>,
        #       ...
        #   }
        user = req.context.auth["user"]
        resp.media = {"message": f"Hello {user['username']}"}


app.add_route("/hello", HelloResource())


async def user_header_loader(attr, user_header):
    # authenticate the user with the user_header
    return user_header


class GenericResource:
    auth = {
        "backend": GenericAuthBackend(user_header_loader, getter=HeaderGetter("User")),
        "exempt_methods": ["GET"],
    }

    async def on_get(self, req, resp):
        resp.media = {"type": "No authentication for GET"}

    async def on_post(self, req, resp):
        resp.media = {"info": f"User header {req.context.auth['user']}"}


app.add_route("/generic", GenericResource())


class NoAuthResource:
    auth = {"auth_disabled": True}

    async def on_get(self, req, resp):
        resp.body = "No auth in this resource"

    async def on_post(self, req, resp):
        resp.body = "No auth in this resource"


app.add_route("/no-auth", NoAuthResource())
