from mitmproxy import http

from detection.common.logger import log_alert

from detection.l7_web import scan_all

class WebDlpAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        client_ip = flow.client_conn.address[0] if flow.client_conn.address else "unknown"
        target_host = flow.request.pretty_host
        body = flow.request.get_text() or ""

        findings = scan_all(body)
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