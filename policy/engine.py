import yaml
import fnmatch
from pathlib import Path

class PolicyEngine:
    def __init__(self, policy_file: str = "policy/policies.yaml"):
        with open(policy_file) as f:
            data = yaml.safe_load(f)
        self.policies = data["policies"]

    def evaluate(self, category: str, confidence: float, 
                 destination: str, bypass_flag: bool) -> tuple[str, str]:
        """
        Returns (action, policy_name)
        action is one of: BLOCK, DRY_RUN, ALLOW
        """
        for policy in self.policies:
            # Handle bypass-only policies
            if policy.get("bypass_only"):
                if bypass_flag:
                    return policy["action"], policy["name"]
                else:
                    continue
    
            # Check category match
            category_match = (
                policy["category"] == "*" or 
                policy["category"] == category
            )

            # Check destination match using wildcard
            destination_match = fnmatch.fnmatch(destination, policy["destination"])

            # Check confidence threshold
            confidence_match = confidence >= policy["min_confidence"]

            if category_match and destination_match and confidence_match:
                return policy["action"], policy["name"]

        return "ALLOW", None