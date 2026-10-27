"""JWT token parsing utilities.

Parse OAuth/OIDC id_tokens and extract useful claims without requiring
external JWT libraries.
"""

import base64
import json
import logging

logger = logging.getLogger(__name__)


def parse_jwt_id_token(id_token: str) -> dict:
    """Parse an OIDC id_token and return all claims.

    Returns an empty dict for malformed or non-JWT tokens.
    Does not validate the signature.
    """
    if not id_token or id_token.count('.') != 2:
        return {}

    try:
        payload_b64 = id_token.split('.')[1]
        # Pad Base64URL payload to a multiple of 4.
        padded = payload_b64 + '=' * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(padded).decode('utf-8')
        payload = json.loads(payload_json)
    except Exception as exc:
        logger.debug('Failed to parse id_token: %s', exc)
        return {}

    return payload


def parse_jwt_header(id_token: str) -> dict:
    """Parse the JWT header and return algorithm/kid/type info."""
    if not id_token or id_token.count('.') != 2:
        return {}
    try:
        header_b64 = id_token.split('.')[0]
        padded = header_b64 + '=' * (-len(header_b64) % 4)
        header_json = base64.urlsafe_b64decode(padded).decode('utf-8')
        return json.loads(header_json)
    except Exception:
        return {}
