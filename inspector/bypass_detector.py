import magic
from pathlib import Path

# These are extensions that attackers commonly use to disguise files
SUSPICIOUS_MISMATCH = {
    ".txt":  ["text/x-python", "application/javascript", "text/x-shellscript"],
    ".jpg":  ["text/plain", "application/json", "text/x-python"],
    ".png":  ["text/plain", "application/json", "text/x-python"],
    ".pdf":  ["text/plain", "text/x-python"],
    ".csv":  ["text/x-python", "application/javascript"],
}

class BypassDetector:
    def __init__(self):
        pass

    @staticmethod
    def detect(filename: str, body: bytes) -> bool:
        extension = Path(filename).suffix.lower()

        mime_type = magic.from_buffer(body, mime=True)

        if (
            extension in SUSPICIOUS_MISMATCH
            and mime_type in SUSPICIOUS_MISMATCH[extension]
        ):
            return True

        return False