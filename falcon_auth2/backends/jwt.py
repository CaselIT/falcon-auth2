from typing import Callable
from typing import List
from typing import Optional
from typing import Union

from falcon import Request

from .base import BaseAuthBackend
from ..exc import BackendNotApplicable
from ..getter import AuthHeaderGetter
from ..getter import Getter
from ..utils import await_
from ..utils import check_getter
from ..utils import RequestAttributes

try:
    from authlib.jose import JoseError
    from authlib.jose import JsonWebToken

    has_authlib = True
except ImportError:  # pragma: no cover
    has_authlib = False


class JWTAuthBackend(BaseAuthBackend):
    """Implements the `JSON Web Token (JWT) standard <https://tools.ietf.org/html/rfc7519>`_.

    Clients should authenticate by passing the token key in the `Authorization`
    HTTP header, prepending it with the type specified in the setting ``auth_header_type``.

    This backend uses the `Authlib <https://authlib.org>`_ library to handle the validation
    of the tokens. See also its `JSON Web Token (JWT)
    <https://docs.authlib.org/en/latest/jose/jwt.html>`_ documentation for additional
    details on the authentication library features.

    Args:
        user_loader (Callable): A callable object that is called with the
            :class:`~.RequestAttributes` object and the token payload obtained after a successful
            validation. It should return the user identified by the token, or ``None``
            if no user could be not found. The token is extracted from the request using
            the provided ``getter``.
            When using falcon in async mode (asgi), this function may also be async.

            Note:
                An error will be raised if an async function is used when using falcon in sync
                mode (wsgi).

            Note:
                Exceptions raised in this callable are not handled directly, and are surfaced to
                falcon.
        key (str, bytes, dict, Callable): The key to use to decode the tokens.
            This parameter is passed to the ``JsonWebToken.decode()`` method and is used to verify
            the signature of the token.
            A key can be passed as string or bytes. Dynamic keys are also supported
            by passing a "JWK set" dict or a callable that is called with the token header
            and payload and returns the key to use to validate the current token signature.
            See `Use dynamic keys
            <https://docs.authlib.org/en/latest/jose/jwt.html#use-dynamic-keys>`_
            for additional details on the supported values.
    Keyword Args:
        auth_header_type (string, optional): The type of authentication required in the
            ``Authorization`` header. This value is added to the ``challenges`` in case of errors.
            Defaults to ``"Bearer"``.

            Note:
                When passing a custom ``getter`` this value is only used to generate the
                ``challenges``, since the provided getter will be used to obtain the credentials
                to authenticate.
        getter (Optional[Getter]): Getter used to extract the authentication token from the
            request. When using a custom getter, the returned value must be a valid jwt token in
            string form (ie not yet parsed).
            Defaults to :class:`~.AuthHeaderGetter` initialized with the provided
            ``auth_header_type``.
        algorithms (str, List[str]): The signing algorithm(s) that should be supported.
            Using a list multiple values may be provided. Defaults to ``"HS256"``.
            Allowed values are listed at `RFC7518: JSON Web Algorithms
            <https://docs.authlib.org/en/latest/specs/rfc7518.html#specs-rfc7518>`_.
        claims_options (dict): The claims to validate in the token. By default the value
            returned by :meth:`.JWTAuthBackend.default_claims` is used.
        leeway (int): Leeway in seconds to pass to the ``JWTClaims.validate()`` call to
            account for clock skew. Defaults to 0.
    """

    def __init__(
        self,
        user_loader: Callable,
        key: Union[str, bytes, dict, Callable[[dict, dict], Union[str, bytes]]],
        *,
        auth_header_type: str = "Bearer",
        getter: Optional[Getter] = None,
        algorithms: Optional[Union[str, List[str]]] = "HS256",
        claims_options: Optional[dict] = None,
        leeway: int = 0,
    ):
        if not has_authlib:
            raise ImportError(f"Authlib is required to use the {self.__class__.__name__} backend.")
        super().__init__(user_loader, challenges=(auth_header_type,))
        if getter:
            check_getter(getter)
        self.auth_header_type = auth_header_type
        self.getter = getter or AuthHeaderGetter(auth_header_type)
        if isinstance(algorithms, str):
            algorithms = [algorithms]
        self.jwt = JsonWebToken(algorithms)
        self.key = key
        self.leeway = leeway
        self.claims_options = self.default_claims() if claims_options is None else claims_options

    def default_claims(self):
        """Returns the default claims to verify in the tokens.

        The default claims check that the 'iss', 'sub', 'aud', 'exp', 'nbf', 'iat' are present in
        the token.

        Subclasses can choose to override this method. The claims may also be passed using the
        ``claims_options`` parameter when instanciating this class.

        See `JWT Payload Claims Validation
        <https://docs.authlib.org/en/latest/jose/jwt.html#jwt-payload-claims-validation>`_
        for additional details on the ``claims_options`` format.
        """
        return {
            "iss": {"essential": True},
            "sub": {"essential": True},
            "aud": {"essential": True},
            "exp": {"essential": True},
            "nbf": {"essential": True},
            "iat": {"essentail": True},
        }

    def _validate_token(self, req: Request, is_async: bool):
        if is_async and not self.getter.async_calls_sync_load:
            token = await_(self.getter.load_async(req, challenges=self.challenges))
        else:
            token = self.getter.load(req, challenges=self.challenges)

        try:
            decoded = self.jwt.decode(token, key=self.key, claims_options=self.claims_options)
            decoded.validate(leeway=self.leeway)
        except JoseError as e:
            raise BackendNotApplicable(
                description=f"Invalid Authorization. Unable to decode or verify token. {e}",
                challenges=self.challenges,
            )

        return decoded

    def authenticate(self, attributes: RequestAttributes) -> dict:
        "Authenticates the request and returns the authenticated user."
        payload = self._validate_token(attributes[0], attributes[-1])
        return {"user": self.load_user(attributes, payload)}
