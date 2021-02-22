import json
from http import HTTPStatus

from flask import (
    Blueprint, Response, request,
)

from intergov.apis.common import auth
from intergov.apis.common.errors import (
    InternalServerError
)
from intergov.apis.common.utils import routing
from intergov.domain.jurisdiction import Jurisdiction
from intergov.domain.uri import URI
from intergov.loggers import logging  # NOQA
from intergov.monitoring import statsd_timer
from intergov.repos.object_acl import ObjectACLRepo
from intergov.repos.object_lake import ObjectLakeRepo
from intergov.use_cases import (
    AuthenticatedObjectAccessUseCase,
    StoreObjectUseCase
)
from .conf import Config
from .exceptions import (
    TooManyFilesError,
    NoInputFileError,
    BadJurisdictionNameError,
    InvalidURIError,
    DocumentNotFoundError
)

logger = logging.getLogger(__name__)

blueprint = Blueprint('documents', __name__)


@blueprint.route('/jurisdictions/<jurisdiction_name>', methods=['POST'])
@blueprint.route('/countries/<jurisdiction_name>', methods=['POST'])
@routing.mimetype(['multipart/form-data'])
@statsd_timer("api.document.endpoint.document_post")
def document_post(jurisdiction_name):
    """
    ---
    post:
      parameters:
      - in: path
        name: jurisdiction_name
        required: true
        schema:
          type: string
      requestBody:
        content:
          application/binary:
            schema:
                format: binary
                type: string
      responses:
        200:
          content:
            application/json:
              schema:
                properties:
                  multihash:
                    format: uuid
                    type: string
                type: object
          description: Returns document id
    """
    try:
        target_jurisdiction = Jurisdiction(jurisdiction_name)
    except Exception as e:
        raise BadJurisdictionNameError(e)

    object_lake_repo = ObjectLakeRepo(Config.OBJECT_LAKE_CONN)
    object_acl_repo = ObjectACLRepo(Config.OBJECT_ACL_CONN)

    if len(request.files) == 0:
        raise NoInputFileError()
    elif len(request.files) > 1:
        raise TooManyFilesError(len(request.files))

    # get the first file, whatever way it's called
    file = request.files[list(request.files.keys())[0]]

    use_case = StoreObjectUseCase(
        object_acl_repo=object_acl_repo,
        object_lake_repo=object_lake_repo,
    )

    try:
        multihash = use_case.execute(fobj=file, target_jurisdiction=target_jurisdiction)
    except Exception as e:
        logger.exception(e)
        raise InternalServerError(e)

    return Response(
        json.dumps({
            "multihash": multihash,
        }),
        mimetype='application/json',
        status=HTTPStatus.OK
    )


@blueprint.route('/<uri>', methods=['GET'])
@auth.jwt
@statsd_timer("api.document.endpoint.document_fetch")
def document_fetch(uri, jwt=None):
    """
    ---
    get:
      parameters:
      - in: path
        name: uri
        required: true
        schema:
          format: uuid
          type: string
      responses:
        200:
          content:
            application/binary:
              schema:
                format: binary
                type: string
          description: Returns document
    """
    try:
        jurisdiction = Jurisdiction(jwt.get('jurisdiction'))
    except Exception as e:
        raise BadJurisdictionNameError(e)

    if not URI(uri).is_valid_multihash():
        raise InvalidURIError()

    object_lake_repo = ObjectLakeRepo(Config.OBJECT_LAKE_CONN)
    object_acl_repo = ObjectACLRepo(Config.OBJECT_ACL_CONN)

    use_case = AuthenticatedObjectAccessUseCase(
        object_acl_repo=object_acl_repo,
        object_lake_repo=object_lake_repo,
    )

    try:
        document_body = use_case.execute(uri, jurisdiction)
    except Exception as e:
        logger.exception(e)
        raise InternalServerError(e)

    if document_body is not None:
        return Response(
            document_body,
            status=HTTPStatus.OK,
            mimetype='binary/octet-stream',  # TODO: correct mimetype?
            # TODO: some information about the file content?
        )
    else:
        raise DocumentNotFoundError(uri, jurisdiction)
