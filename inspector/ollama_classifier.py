import json
import ollama

class OllamaClassifier:
    def __init__(self, model: str = "llama3.2"):
        self.model = model

    def classify(self, body: bytes) -> tuple[str, float]:
        try:
            snippet = body.decode("utf-8", errors="ignore")[:500]

            prompt = f"""You are a data security classifier. Analyze the following content and classify it.

Reply with ONLY a JSON object in this exact format, nothing else:
{{"category": "<category>", "confidence": <float>}}

Categories to use:
- "source_code" — programming code in any language
- "credentials" — passwords, API keys, tokens, secrets
- "pii" — personal information like names, emails, phone numbers, SSNs
- "ip" — internal documents, business plans, proprietary information
- "clean" — nothing sensitive

Content to classify:
{snippet}"""

            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}]
            )

            raw = response["message"]["content"].strip()
            raw = raw.replace("```json", "").replace("```", "").strip()

            result = json.loads(raw)

            category = result.get("category", "clean")
            confidence = float(result.get("confidence", 0.0))

            return category, confidence

        except Exception:
            return "clean", 0.0