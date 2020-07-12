import falcon
from falcon_auth2 import AuthMiddleware, HeaderGetter
from falcon_auth2.backends import BasicAuthBackend, GenericAuthBackend


def authenticate(user, password):
    # check if the user exists and the password match
    return False


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
        #       '<backend specific item>': <some extra data from the backend>,
        #       ...
        #   }
        user = req.context.auth["user"]
        resp.media = {"message": f"Hello {user['username']}"}


app.add_route("/hello", HelloResource())


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
