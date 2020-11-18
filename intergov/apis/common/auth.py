"""
This authorization mechanism works with the assumption that JWT verification done by APIGateway + Cognito
"""


import json
import base64
from functools import wraps
from http import HTTPStatus as StatusCode

from flask import request

from intergov.loggers import logging
from intergov.apis.common.errors import BaseError


logger = logging.getLogger(__name__)

AUTHORIZATION_HEADER = "Authorization"
TOKEN_PREFIX = "Bearer"


class AuthorizationError(BaseError):
    status = StatusCode.UNAUTHORIZED


def jwt(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header_content = request.headers.get(AUTHORIZATION_HEADER, '').strip()
        if not auth_header_content:
            raise AuthorizationError(detail="Unknown or no auth")

        if not auth_header_content.startswith(TOKEN_PREFIX):
            raise AuthorizationError(detail="Invalid Authorization prefix, must be \"{}\"".format(TOKEN_PREFIX))

        try:
            # adding maximum required number of padding characters
            jwtbody_base64_content = auth_header_content.split('.')[1] + "==="
        except IndexError:
            raise AuthorizationError(detail="Invalid JWT format, must be base64_header.base64_body.signature")
        try:
            jwtbody_content = base64.urlsafe_b64decode(jwtbody_base64_content)
        except Exception:
            raise AuthorizationError(detail="Can't decode base64 JWT body")

        try:
            jwtbody = json.loads(jwtbody_content)
        except Exception:
            raise AuthorizationError(detail="Can't parse JWT body JSON data")
        return func(*args, jwt=jwtbody, **kwargs)
    return wrapper
