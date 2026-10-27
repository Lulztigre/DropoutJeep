"""Clean URL path obfuscation utilities.

Builds opaque, path-based recipient URLs such as ``https://<base>/l/<token>``
that redirect to the real landing or proxy path when visited.
"""


def build_clean_url(base_url: str, recipient_token: str) -> str:
    """Return an opaque path-based URL for a recipient token.

    Args:
        base_url: The campaign base URL (e.g. ``https://phish.example.com``).
        recipient_token: The recipient's unique token.

    Returns:
        A URL of the form ``https://<base>/l/<token>``.
    """
    if not base_url:
        base_url = ''
    base_url = base_url.rstrip('/')
    return f"{base_url}/l/{recipient_token}"
