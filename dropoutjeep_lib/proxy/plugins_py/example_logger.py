"""Example Python proxy plugin.

This plugin logs every proxied exchange to the DropoutJeep log. It is a safe
starting point for writing custom request/response transformers.
"""

from dropoutjeep_lib.proxy.plugin_system import ProxyPlugin, HTTPExchange


class LoggerPlugin(ProxyPlugin):
    name = "example_logger"

    def on_request(self, request, ctx):
        print(f"[example_logger] -> {request.method} {request.path}")
        return request

    def on_response(self, request, response, ctx):
        print(f"[example_logger] <- {response.status_code} {request.path}")
        return response

    def on_exchange(self, exchange: HTTPExchange):
        print(f"[example_logger] exchange {exchange.method} {exchange.path} "
              f"campaign={exchange.campaign_id}")


plugin = LoggerPlugin()
