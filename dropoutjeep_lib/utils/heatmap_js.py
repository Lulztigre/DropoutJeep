"""JavaScript snippet for click heatmap tracking.

Inject this into proxied/landing pages. It records click coordinates and the
clicked element selector, then POSTs them to /track/heatmap.
"""


def build_heatmap_script(campaign_id: int, token: str | None = None) -> str:
    """Return the heatmap tracking script for a campaign."""
    token_js = f"'{token}'" if token else 'null'
    return f"""
<script>
(function() {{
  function getSelector(el) {{
    if (el.id) return '#' + el.id;
    if (el.className) return el.tagName.toLowerCase() + '.' + el.className.split(' ').join('.');
    return el.tagName.toLowerCase();
  }}
  document.addEventListener('click', function(e) {{
    var data = {{
      campaign_id: {campaign_id},
      token: {token_js},
      x: e.clientX,
      y: e.clientY,
      selector: getSelector(e.target),
      path: window.location.pathname + window.location.search
    }};
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/track/heatmap', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify(data));
  }});
}})();
</script>
"""
