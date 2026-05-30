from inspector.yara_classifier import YARAClassifier
from inspector.regex_classifier import RegexClassifier
from inspector.ollama_classifier import OllamaClassifier
from inspector.bypass_detector import BypassDetector

regex_classifier = RegexClassifier()
yara_classifier = YARAClassifier()
ollama_classifier = OllamaClassifier()
bypass_detector = BypassDetector()

CONFIDENCE_THRESHOLD = 0.75

def inspect(filename: str, body: bytes) -> dict:
    result = {
        "category": "clean",
        "confidence": 0.0,
        "detected_by": "none",
        "bypass_flag": False,
        "action": "ALLOW"
    }

     # Run bypass detector first — independent of classification
    bypass = BypassDetector()
    if bypass.detect(filename, body):
        result["bypass_flag"] = True

    category, confidence = regex_classifier.classify(body)
    
    if confidence > CONFIDENCE_THRESHOLD:
        result["category"] = category
        result["confidence"] = confidence
        result["detected_by"] = "regex"
        return result
    
    category, confidence = yara_classifier.classify(body)

    if confidence > CONFIDENCE_THRESHOLD:
        result["category"] = category
        result["confidence"] = confidence
        result["detected_by"] = "yara"
        return result

    
    category, confidence = ollama_classifier.classify(body)
    result["category"] = category
    result["confidence"] = confidence
    result["detected_by"] = "ollama"
    return result