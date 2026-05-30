import base64
import requests
from mitmproxy import http

INSPECT_URL = "http://localhost:8000/inspect"

# Only intercept uploads to these destinations
WATCHED_DESTINATIONS = [
    "googleapis.com",
    "dropbox.com",
    "api.dropboxapi.com",
    "localhost"
]

def is_watched(host: str) -> bool:
    return any(host.endswith(dest) for dest in WATCHED_DESTINATIONS)

def is_upload(flow: http.HTTPFlow) -> bool:
    return flow.request.method in ("POST", "PUT")

class CASBAddon:
    def request(self, flow: http.HTTPFlow):
        print(f"[DEBUG] Saw request: {flow.request.method} {flow.request.pretty_host}{flow.request.path}")

        host = flow.request.pretty_host

        if not is_upload(flow) or not is_watched(host):
            return  # not interested in this request, let it pass

        # Read the body
        body = flow.request.get_content()
        if not body:
            return

        # Get filename from headers or URL — fall back to "unknown"
        filename = (
            flow.request.headers.get("X-File-Name") or
            flow.request.path.split("/")[-1] or
            "unknown"
        )

        # Get client IP
        user_ip = flow.client_conn.peername[0]

        # Call your FastAPI inspector
        try:
            response = requests.post(INSPECT_URL, json={
                "filename": filename,
                "destination": host,
                "user_ip": user_ip,
                "body_b64": base64.b64encode(body).decode()
            }, timeout=30)

            print(f"[DEBUG] Inspector status: {response.status_code}")
            print(f"[DEBUG] Inspector response: {response.text}")
            
            result = response.json()

        except Exception as e:
            # If inspector is down, fail open — let traffic through
            print(f"[CASB] Inspector unreachable: {e}")
            return

        # Act on the policy decision
        action = result.get("action", "ALLOW")
        category = result.get("category", "unknown")
        confidence = result.get("confidence", 0.0)
        bypass = result.get("bypass_flag", False)

        if action == "BLOCK":
            reason = f"Policy violation: {category} (confidence: {confidence:.0%})"
            if bypass:
                reason += " [BYPASS ATTEMPT DETECTED]"

            flow.response = http.Response.make(
                403,
                f"CASB BLOCKED: {reason}",
                {"Content-Type": "text/plain"}
            )
            print(f"[CASB] BLOCKED {filename} → {host} | {reason}")

        elif action == "DRY_RUN":
            # Let it through but log it
            print(f"[CASB] DRY_RUN {filename} → {host} | {category} ({confidence:.0%})")

        else:
            print(f"[CASB] ALLOWED {filename} → {host}")


# mitmproxy entry point — this is how it loads your addon
addons = [CASBAddon()]