from mitmproxy import http

from detection.common.logger import log_alert


class WebDlpAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        client_ip = flow.client_conn.address[0] if flow.client_conn.address else "unknown"
        target_host = flow.request.pretty_host
        body = flow.request.get_text() or ""

        # Dummy rule: flag and block if payload contains "SECRET"
        if "SECRET" in body or any("SECRET" in v for v in flow.request.headers.values()):
            log_alert(
                channel="L7_WEB",
                rule_id="SECRET_KEYWORD_DETECTED",
                severity="HIGH",
                source_ip=client_ip,
                destination=target_host,
                details={"matched": "SECRET"},
                blocked=True,
            )
            flow.response = http.Response.make(
                403,
                b"HTTP 403 Forbidden: Blocked by DLP Gateway.\n",
                {"Content-Type": "text/plain"},
            )

addons = [WebDlpAddon()]