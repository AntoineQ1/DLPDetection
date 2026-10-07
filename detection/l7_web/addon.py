from collections.abc import Callable

from mitmproxy import http

from detection.common.logger import log_alert
from detection.common.mask import mask
from detection.l7_web import scan_all
from detection.l7_web.decoder import decode_body


class WebDlpAddon:
    def __init__(self, scanner: Callable[[str], list] = scan_all):
        self.scanner = scanner

    def request(self, flow: http.HTTPFlow) -> None:
        client_ip = (
            flow.client_conn.address[0] if flow.client_conn.address else "unknown"
        )
        target_host = flow.request.pretty_host
        content_type = flow.request.headers.get("content-type", "")

        findings = []

        # 1. Inspection URL et Query string
        findings.extend(self.scanner(flow.request.path))
        for key, value in flow.request.query.items():
            findings.extend(self.scanner(key))
            findings.extend(self.scanner(value))

        # 2. Inspection Body
        content = flow.request.content or b""
        for value in decode_body(content, content_type):
            findings.extend(self.scanner(value))

        if findings:
            log_alert(
                channel="L7_WEB",
                rule_id=findings[0].rule_id,
                severity=findings[0].severity.upper(),
                source_ip=client_ip,
                destination=target_host,
                details={
                    "findings": [
                        {"rule_id": f.rule_id, "matched": mask(f.matched)} for f in findings
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
