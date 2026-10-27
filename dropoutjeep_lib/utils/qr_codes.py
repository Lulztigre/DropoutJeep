"""QR code generation for per-recipient campaign tracking URLs.

Templates can include ``{{QR_CODE}}`` when a campaign has
``flow_config.qr_code_enabled`` set. The rendered value is an inline
``<img>`` tag with a base64-encoded PNG QR code that points at the
recipient's tracking URL.
"""

import base64
import io
import logging

from .clean_urls import build_clean_url
from .redirectors import wrap_campaign_link
from .validator import sign_token

logger = logging.getLogger(__name__)


def _qr_module():
    """Lazy import qrcode so missing dependency does not break startup."""
    try:
        import qrcode
        return qrcode
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("qrcode[pil] is required for QR campaigns") from exc


def generate_qr_png(url: str, box_size: int = 6, border: int = 2) -> bytes:
    """Return a PNG byte stream encoding ``url`` as a QR code."""
    qrcode = _qr_module()
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def build_qr_data_uri(url: str) -> str:
    """Return a ``data:image/png;base64,...`` URI for the QR code."""
    png = generate_qr_png(url)
    b64 = base64.b64encode(png).decode("ascii")
    return f"data:image/png;base64,{b64}"


def build_qr_img_tag(url: str, alt: str = "QR code") -> str:
    """Return a self-contained ``<img>`` tag for the QR code."""
    return f'<img src="{build_qr_data_uri(url)}" alt="{alt}" width="200" height="200" />'


def get_recipient_qr_url(campaign, recipient, base_url: str) -> str:
    """Build the tracking URL a QR code should encode.

    Uses the same tracked link the email body uses so scans are attributed to
    the recipient and can pass through configured redirector chains.
    """
    base_url = (base_url or "").rstrip("/")
    token = recipient.token
    sig = sign_token(token)
    track_url = f"{base_url}/track/{token}?sig={sig}"
    return wrap_campaign_link(track_url, campaign)


def build_recipient_qr_img(campaign, recipient, base_url: str) -> str:
    """Return an inline ``<img>`` tag with a QR code for the recipient."""
    url = get_recipient_qr_url(campaign, recipient, base_url)
    return build_qr_img_tag(url, alt=f"QR code for {recipient.email}")
