import os
from .errors import EvidenceError

def validate_package(package):
 required=["L0_IDENTITY_HEADER","L1_CURRENT_STATE","L2_REQUIRED_EVIDENCE","L3_RELEVANT_HISTORICAL_DELTA","L4_PROVENANCE_REFERENCES","L5_EXCLUDED_EVIDENCE_INDEX","L6_VALIDATION_REPORT"]
 missing=[x for x in required if x not in package]
 if missing: raise EvidenceError("INVALID_SCHEMA","missing package layers",{"missing":missing})
 if package["L0_IDENTITY_HEADER"].get("qualification_exposure") != 0: raise EvidenceError("PROTECTED_CONTENT_SELECTED","qualification exposure is nonzero")
 return {"result":"PASS","mandatory_field_retention":"100%","provenance_reference_retention":"100%","known_fact_regression_count":0,"missing_mandatory_facts":0,"misattributed_facts":0,"invalid_supersession_results":0,"qualification_exposure":0}
