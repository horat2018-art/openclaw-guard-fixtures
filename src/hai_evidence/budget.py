def classify(raw_tokens, protected=False, full_raw=False):
 if protected: return "PROTECTED_BLOCKED"
 if full_raw: return "FULL_RAW_REQUIRED"
 return "HIGH_CONTEXT" if raw_tokens > 4000 else "NORMAL"
