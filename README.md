# falcon-auth2

[![build](https://github.com/CaselIT/falcon-auth2/workflows/Run%20tests/badge.svg)](https://github.com/CaselIT/falcon-auth2/actions?query=workflow%3A%22Run+tests%22)
[![pypi](https://img.shields.io/pypi/v/falcon-auth2.svg)](https://pypi.python.org/pypi/falcon-auth2)
[![Documentation Status](https://readthedocs.org/projects/falcon-auth2/badge/?version=latest)](https://falcon-auth2.readthedocs.io/en/latest/?badge=latest)
[![codecov](https://codecov.io/gh/CaselIT/falcon-auth2/branch/master/graph/badge.svg)](https://codecov.io/gh/CaselIT/falcon-auth2)

Falcon authentication middleware that supports multiple authentication schemes. 

## Install

```sh
$ pip install falcon-auth2[jwt]
```
The above will install `falcon-auth2` and also the dependencies to use the ``JWT`` authentication backend.  
If you plan to use async falcon with ASGI run:
```sh
$ pip install falcon-auth2[jwt, async]
```

## Usage

This package provides a falcon middleware to authenticate incoming requests using the selected authentication backend. The middleware allows excluding some routes or method from authentication. After a successful authentication the middleware adds the user identified by the request to the ``request context``.
When using falcon v3+, the middleware also supports async execution.

See [readme_example](./examples/readme_example.py) and [readme_example_async](./examples/readme_example_async.py) for complete examples.

```py
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
```

### Override Authentication for a resource

The middleware allows each resource to customize the backend used for authentication or the excluded methods. A resource can also specify that does not need authentication.

```py
from falcon_auth2 import HeaderGetter
from falcon_auth2.backends import GenericAuthBackend

def user_header_loader(attr, user_header):
    # authenticate the user with the user_header
    return user_header

class GenericResource:
    auth = {
        "backend": GenericAuthBackend(user_header_loader, getter=HeaderGetter("User")),
        "exempt_methods": ["GET"],
    }

    def on_get(self, req, resp):
        resp.media = {"type": "No authentication for GET"}

    def on_post(self, req, resp):
        resp.media = {"info": f"User header {req.context.auth['user']}"}

app.add_route("/generic", GenericResource())

class NoAuthResource:
    auth = {"auth_disabled": True}

    def on_get(self, req, resp):
        resp.text = "No auth in this resource"

    def on_post(self, req, resp):
        resp.text = "No auth in this resource"

app.add_route("/no-auth", NoAuthResource())

```

## Included Authentication backends

#### `BasicAuthBackend`

Implements [HTTP Basic Authentication](https://tools.ietf.org/html/rfc7617) where clients should authenticate by passing the credential in the format ``username:password`` encoded in ``base64`` in the ``Authorization`` HTTP header.

#### `JWTAuthBackend`

Implements [JSON Web Token (JWT) standard](https://tools.ietf.org/html/rfc7519) where clients should authenticate by passing the token key in the `Authorization` HTTP header. This backend makes use of the
[Authlib](https://authlib.org) library.

#### `GenericAuthBackend`

Generic authentication backend that delegates the verification of the authentication information from the request to the ``user_loader`` callable. This backend can be used to quickly implement custom authentication schemes or as an adapter to other authentication libraries.

#### `NoAuthBackend`

Backend that does not perform any authentication check and may be useful to provide a fallback for unauthenticated users when combined with `MultiAuthBackend`.

### Meta Authentication backends

#### `CallBackBackend`

Notifies when another backend has success and/or fails to authenticate a request. This backend delegates all the authentication actions to the provided ``backend``.

#### `MultiAuthBackend`

Backend used to combine multiple authentication backends.
This backend successfully authenticates a request if one of the provided backends can authenticate the request.

## About Falcon

[Falcon](https://falconframework.org) is the minimalist web API framework
for building reliable, correct, and high-performance REST APIs, microservices,
proxies, and app backends in Python.

## Thanks

This package was inspired by [falcon-auth](https://github.com/loanzen/falcon-auth) and [falcon-authentication](https://github.com/jcwilson/falcon-authentication) packages.

## License

`falcon-auth2` is distributed under the [Apache-2.0 License](https://github.com/CaselIT/falcon-auth2/blob/master/LICENSE).
