class EvidenceError(Exception):
    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code = code
        self.details = details or {}

EXIT_CODES = {
    "PASS": 0, "VALIDATION_FAILURE": 1, "INPUT_SCHEMA_FAILURE": 2,
    "SECURITY_BLOCK": 3, "PROVENANCE_FAILURE": 4, "DETERMINISM_FAILURE": 5,
}
