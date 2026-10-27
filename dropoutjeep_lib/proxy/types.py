"""Shared request/response types for the proxy engine and plugin system."""


class Request:
    def __init__(self, method, path, headers, query_params, body):
        self.method = method
        self.path = path
        self.headers = headers
        self.query_params = query_params
        self.body = body


class Response:
    def __init__(self, status_code, headers, body, raw_body: bytes | None = None,
                 passthrough: bool = False):
        self.status_code = status_code
        self.headers = headers
        self.body = body
        # When passthrough is True, body should be returned raw without further
        # modification. raw_body holds the original bytes.
        self.passthrough = passthrough
        self.raw_body = raw_body
