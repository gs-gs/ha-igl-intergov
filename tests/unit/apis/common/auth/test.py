import json
import base64
from http import HTTPStatus
from flask import jsonify
from intergov.apis.common import auth


ROLE_USER = 'user'
ROLE_ADMIN = 'admin'

JWT_PREFIX = 'Bearer'
JWT_HEADER = {
  "alg": "HS256",
  "typ": "JWT"
}
JWT_SIGNATURE = "xxxxxxxxxxxxx"


def _create_auth_headers(
    payload=None,
    header=None,
    signature=None,
    prefix=None,
    base64_encode=True
):

    header = header or JWT_HEADER
    signature = signature or JWT_SIGNATURE
    prefix = prefix or JWT_PREFIX
    if base64_encode:
        payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode()

    header = {
        'Authorization': f'{prefix} {header}.{payload}.{signature}'
    }
    return header


def test(app, client):
    @app.route('/jwt', methods=['GET'])
    @auth.jwt
    def jwt_test(jwt=None):
        return jsonify(jwt)
    # test successful auth
    jwt_payload = {"msg": "Hello world"}
    resp = client.get(
        '/jwt',
        headers=_create_auth_headers(jwt_payload)
    )
    assert resp.status_code == HTTPStatus.OK
    assert resp.json == jwt_payload
    # test no header
    resp = client.get(
        '/jwt',
        headers={}
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.json['errors'][0] == auth.AuthorizationError(
        detail="Unknown or no auth"
    ).to_dict()
    # test invalid prefix
    resp = client.get(
        '/jwt',
        headers=_create_auth_headers(jwt_payload, prefix='invalid_prefix')
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.json['errors'][0] == auth.AuthorizationError(
        detail="Invalid Authorization prefix, must be \"Bearer\""
    ).to_dict()

    # test invalid jwt format
    resp = client.get(
        '/jwt',
        headers={
            'Authorization': "Bearer xxx"
        }
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.json['errors'][0] == auth.AuthorizationError(
        detail="Invalid JWT format, must be base64_header.base64_body.signature"
    ).to_dict()

    # test not base64 encoded
    resp = client.get(
        '/jwt',
        headers=_create_auth_headers(jwt_payload, base64_encode=False)
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.json['errors'][0] == auth.AuthorizationError(
        detail="Can't decode base64 JWT body"
    ).to_dict()

    # test not JSON payload
    resp = client.get(
        '/jwt',
        headers={'Authorization': f"Bearer xxx.{base64.urlsafe_b64encode('Hello world'.encode()).decode()}"}
    )
    assert resp.status_code == HTTPStatus.UNAUTHORIZED
    assert resp.json['errors'][0] == auth.AuthorizationError(
        detail="Can't parse JWT body JSON data"
    ).to_dict()
