from jinja2 import Environment, BaseLoader, select_autoescape

env = Environment(
    loader=BaseLoader(),
    autoescape=select_autoescape(['html', 'xml'])
)


def render_email(template_html, context):
    t = env.from_string(template_html)
    return t.render(**context)


def render_landing(landing_html, context):
    t = env.from_string(landing_html)
    return t.render(**context)
