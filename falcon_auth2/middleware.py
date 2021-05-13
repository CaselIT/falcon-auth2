from typing import Any
from typing import Iterable
from typing import Tuple

from falcon import Request
from falcon import Response

from .backends import AuthBackend
from .utils import check_backend
from .utils import greenlet_spawn
from .utils import RequestAttributes


class AuthMiddleware:
    """Falcon middleware that can be used to authenticate a request.

    The authentication backend returns an authenticated user which is then set by default in
    ``request.context.auth["user"]``. In case of errors ``falcon.HTTPUnauthorized`` is raised.
    In addition to the ``"user"``, the authenticating backend is returned in the ``"backend"`` key.
    A backend may also store additional information in this dict.

    This middleware supports a global authentication configuration using provided
    :class:`.AuthBackend`, as well as per resource configuration.
    To override the authentication configuration a resource can specify an optional ``auth``
    attribute the override properties. The ``auth`` attribute is a dict that can specify the keys:

        * ``auth_disabled`` boolean. ``True`` disables the authentication on the resource.
        * ``exempt_methods`` iterable that overrides the global ``exempt_methods`` for the resource.
        * ``backend`` backend instace that overrides the globally configured backend used to
          handle the authentication of the request.

    Args:
        backend (AuthBackend): The default auth backend to be used to authenticate requests.
            A resource can override this value by providing a ``backend`` key in its ``auth``
            attribute
    Keyword Args:
        exempt_templates (Iterable[str], optional): A list of paths templates to be excluded
            from the authentication. This value cannot be overridden by a resource.
            Defaults to ``()``.
        exempt_methods (Iterable[str], optional): A list of http methods to be excluded from the
            authentication. A resource can override this value by providing a ``exempt_methods``
            key in its ``auth`` attribute. Defaults to ``("OPTIONS",)``.
        context_attr (str, optional): The attribute of the ``req.context`` object that will store
            the authentication information after a successful precessing. Defaults to ``"auth"``.
    """

    def __init__(
        self,
        backend: AuthBackend,
        *,
        exempt_templates: Iterable[str] = (),
        exempt_methods: Iterable[str] = ("OPTIONS",),
        context_attr: str = "auth",
    ):
        check_backend(backend)
        self.backend = backend
        self.exempt_templates = frozenset(exempt_templates)
        self.exempt_methods = frozenset(exempt_methods)
        self.context_attr = context_attr

    def _get_auth_settings(self, resource: Any) -> Tuple[bool, frozenset, AuthBackend]:
        "Returns a tuple with the configuration to use for this resource."
        auth_settings = getattr(resource, "auth", None)
        if auth_settings:
            return (
                auth_settings.get("auth_disabled", False),
                auth_settings.get("exempt_methods", self.exempt_methods),
                auth_settings.get("backend", self.backend),
            )
        return False, self.exempt_methods, self.backend

    def _process_resource(self, attributes: RequestAttributes):
        "Processes a resource"
        req = attributes[0]
        if req.uri_template in self.exempt_templates:
            return
        skip, exempt_methods, backend = self._get_auth_settings(attributes[2])
        if skip or req.method in exempt_methods:
            return

        results = backend.authenticate(attributes)
        results.setdefault("backend", backend)
        setattr(req.context, self.context_attr, results)

    def process_resource(self, req: Request, resp: Response, resource: Any, params: dict):
        """Called by falcon when processing a resource.

        It will obtain the configuration to use on the resource and, if required, call the
        provided backend to authenticate the request.
        """
        self._process_resource(RequestAttributes(req, resp, resource, params, False))

    async def process_resource_async(
        self, req: Request, resp: Response, resource: Any, params: dict
    ):
        """Called by async falcon when processing a resource.

        It will obtain the configuration to use on the resource and, if required, call the
        provided backend to authenticate the request.
        """
        await greenlet_spawn(
            self._process_resource, RequestAttributes(req, resp, resource, params, True)
        )
