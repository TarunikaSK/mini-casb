import re
import yaml
from pathlib import Path


class RegexClassifier:
    def __init__(self, rules_path: str = "inspector/regex_rules.yaml"):
        self.rules = self._load_rules(rules_path)

    def _load_rules(self, path: str) -> list[dict]:
        with open(Path(path), "r") as f:
            data = yaml.safe_load(f)
        
        compiled = []
        for rule in data["rules"]:
            compiled.append({
                "name": rule["name"],
                "category": rule["category"],
                "pattern": re.compile(rule["pattern"]),
                "confidence": rule["confidence"],
            })
        
        return compiled

    def classify(self, body: bytes) -> tuple[str, float]:
        text = body.decode("utf-8", errors="ignore")
        
        best_category = "clean"
        best_confidence = 0.0
        
        for rule in self.rules:
            match = rule["pattern"].search(text)
            if match and rule["confidence"] > best_confidence:
                best_category = rule["category"]
                best_confidence = rule["confidence"]
        
        return best_category, best_confidence