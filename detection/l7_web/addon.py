from mitmproxy import http

from detection.common.logger import log_alert
from detection.l7_web import scan_all
from detection.l7_web.decoder import decode_body


class WebDlpAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        client_ip = (
            flow.client_conn.address[0] if flow.client_conn.address else "unknown"
        )
        target_host = flow.request.pretty_host

        findings = []

        # Path & Query strings
        findings.extend(scan_all(flow.request.path))
        for key, value in flow.request.query.items():
            findings.extend(scan_all(key))
            findings.extend(scan_all(value))

        # Body
        content = flow.request.content or b""
        content_type = flow.request.headers.get("content-type", "")
        for value in decode_body(content, content_type):
            findings.extend(scan_all(value))

        if findings:
            log_alert(
                channel="L7_WEB",
                rule_id=findings[0].rule_id,
                severity=findings[0].severity.upper(),
                source_ip=client_ip,
                destination=target_host,
                details={
                    "findings": [
                        {"rule_id": f.rule_id, "matched": f.matched} for f in findings
                    ]
                },
                blocked=True,
            )
            flow.response = http.Response.make(
                403,
                b"HTTP 403 Forbidden: Blocked by DLP Gateway.\n",
                {"Content-Type": "text/plain"},
            )


addons = [WebDlpAddon()]
