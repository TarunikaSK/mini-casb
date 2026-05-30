from policy.engine import PolicyEngine

engine = PolicyEngine()

def test_source_code_to_gdrive_is_blocked():
    action, policy = engine.evaluate("source_code", 0.9, "drive.googleapis.com", False)
    assert action == "BLOCK"

def test_bypass_attempt_is_always_blocked():
    action, policy = engine.evaluate("clean", 0.0, "anywhere.com", True)
    assert action == "BLOCK"
    assert policy == "block_bypass_attempts"

def test_low_confidence_is_allowed():
    action, policy = engine.evaluate("source_code", 0.3, "drive.googleapis.com", False)
    assert action == "ALLOW"

def test_pii_is_dry_run():
    action, policy = engine.evaluate("pii", 0.8, "dropbox.com", False)
    assert action == "DRY_RUN"