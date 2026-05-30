import yara
from pathlib import Path


class YARAClassifier:
    def __init__(self):
        filepaths = {p.stem: str(p) for p in Path("rules").glob("*.yar")}
        self.rules = yara.compile(filepaths=filepaths)
    
    def classify(self, body: bytes) -> tuple[str, float]:
        matches = self.rules.match(data=body)
        
        best_category = "clean"
        best_confidence = 0.0

        for match in matches:
            category = match.meta.get("category")
            confidence = float(match.meta.get("confidence", 0.0))
    
            if category and confidence > best_confidence:
                best_category = category
                best_confidence = confidence
        
        return best_category, best_confidence