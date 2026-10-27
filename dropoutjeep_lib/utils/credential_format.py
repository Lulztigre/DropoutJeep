"""Helpers for storing and displaying credential_attempt event metadata.

When a campaign is configured not to store credentials in plaintext, the values
are encrypted with the same Fernet key used for other secrets. The field names
and non-credential metadata remain readable so analysts still know which fields
were submitted.
"""

import json

from dropoutjeep_lib.models import _decrypt_secret, _encrypt_secret


def secure_credential_inputs(inputs: dict, plaintext: bool = False) -> dict:
    """Return a copy of submitted form inputs, encrypting values unless plaintext storage is enabled."""
    if plaintext:
        return inputs
    secured = {}
    for key, value in inputs.items():
        if isinstance(value, str) and value:
            secured[key] = _encrypt_secret(value)
        else:
            secured[key] = value
    return secured


def decrypt_credential_meta(meta: str | None) -> str:
    """Decrypt any enc:: values inside a credential_attempt event's JSON metadata."""
    if not meta:
        return ''
    try:
        data = json.loads(meta)
    except Exception:
        return meta
    if not isinstance(data, dict):
        return meta

    decrypted = {}
    for key, value in data.items():
        if isinstance(value, str) and value.startswith('enc::'):
            decrypted[key] = _decrypt_secret(value)
        else:
            decrypted[key] = value
    return json.dumps(decrypted, default=str)
