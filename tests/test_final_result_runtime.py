import copy
import unittest

from hai_mr05 import cloud_boundary, context_builder, disclosure, discovery, evidence, human_gate, identity, metrics, mr03_adapter, mr04_adapter, normalization, proposal, provenance, verifier
from hai_mr05.canonical import canonical_json_bytes
from hai_mr05.failures import Failure, FailureCode, FailureOwner, FailureSeverity, FailureState


class FinalResultRuntimeTests(unittest.TestCase):
    @staticmethod
    def _task(task_id="mr14g-final-result"):
        return {"schema_version":"1.0.0","task_id":task_id,"task_type":"EVIDENCE_REVIEW","task_text":"Review supplied deterministic evidence.","requested_output_type":"EVIDENCE_REVIEW","allowed_scope":["inspect supplied data"],"prohibited_scope":["execute external actions"],"human_constraints":{"approval_required":True,"no_execution":True,"no_external_side_effects":True,"trust_level":"LEVEL 0","live_cloud_allowed":False,"local_model_source_authority":False},"source_scope":{"approved_source_aliases":["fixture"],"allowed_source_types":["LOCAL_FILE"]},"risk_class_if_known":"UNKNOWN"}

    @staticmethod
    def _descriptor(raw=b'{"cloud":1}', locator="cloud.json"):
        payload={"schema_version":"1.0.0","source_type":"LOCAL_FILE","canonical_locator":{"source_alias":"fixture","relative_path":locator},"content_identity":{"algorithm":"SHA-256","sha256":identity.sha256_bytes(raw)},"content_size_bytes":len(raw),"classification":"PUBLIC","immutability_status":"IMMUTABLE_CAPTURE","availability_status":"AVAILABLE","provenance_owner":"test-fixture"}
        return {**payload,"source_id":discovery.source_descriptor_identity(payload)}

    @staticmethod
    def _dependency_record(discovered, normalized, source_ref, role, upstream=None):
        if role == "MR03_PACKAGER":
            dependency={"dependency_role":"MR03_PACKAGER","dependency_logical_id":"MR03","expected_dependency_class":"FROZEN_MR03_EVIDENCE_PACKAGER","dependency_contract_identity":None,"dependency_version_identity":"MR03-PACKAGE-V1","dependency_content_identity":{"kind":"COMMITTED_FILESET","sha256":"3e85d8eebc1eef05a5ee6e9f18701e0686cb21c0cec6599df32ec09e1168dc48"},"dependency_snapshot":{"commit":"945559bf0f1811cb2f88e827ff1412081f1fbd75","parent":"44ef1ef7f202c8a7ff85cb8f3a329d9ef76fd5e3","tree":"09dfcd9ff69362ae019b2876a66ec78d54008337","pathset_sha256":None}}
        else:
            dependency={"dependency_role":"MR04_GUARD","dependency_logical_id":"MR04","expected_dependency_class":"FROZEN_MR04_LOWER_LEVEL_COMPOSITION","dependency_contract_identity":"0e110454fdd399db1564a2f7fdc581faabbea190ba0d668fc674243bbb414e32","dependency_version_identity":None,"dependency_content_identity":{"kind":"CONTENTSET","sha256":"a1da9509f5e5acc102be249978323bc9706cc893f178f96b70b9317750687b5f"},"dependency_snapshot":{"commit":"8ce9eb8a542799e00088a6654e1061405fde7d33","parent":"85c3f65e23aba4c7307b5870d73c8192a72b46f5","tree":"a8944259034b699c285e2b8551ad60e3ee79d5c2","pathset_sha256":"2b58d0ee14b2c8280b608ea9a8717228c68675d15630a80a2d06f63212ba4640"}}
        dependency.update({"schema_version":"1.0.0","source_ref":source_ref,"input_binding":{"task_identity":discovered.task_identity,"source_set_identity":discovered.source_set_identity,"discovery_identity":discovered.discovery_identity,"normalization_identity":normalized.normalization_identity,"upstream_dependency_identity":upstream}})
        return dependency

    @classmethod
    def _bounded_context_and_metrics(cls, *, raw=b'{"cloud":1}', task_id="mr14g-final-result", locator="cloud.json"):
        source=cls._descriptor(raw,locator)
        discovered=discovery.discover(cls._task(task_id),[source],max_item_count=1,max_bytes=1000)
        row=normalization.NormalizedItem.from_source(discovered.selected_sources[0],phase_id="MR14G",artifact_type="EVIDENCE",current_validity="VALID",supersession="NONE",classification="PUBLIC",mandatory=True)
        normalized=normalization.normalize(discovered,[row])
        source_ref={"schema_version":"1.0.0",**discovered.selected_sources[0].to_dict()}
        mr03=mr03_adapter.bind_mr03_dependency(cls._dependency_record(discovered,normalized,source_ref,"MR03_PACKAGER"),discovered,normalized,source_ref)
        mr04=mr04_adapter.bind_mr04_dependency(cls._dependency_record(discovered,normalized,source_ref,"MR04_GUARD",mr03.binding_identity),discovered,normalized,mr03.binding_identity,source_ref)
        metric=metrics.Metrics(raw_source_bytes=discovered.total_selected_bytes,normalized_bytes=normalized.output_bytes,package_bytes=normalized.output_bytes,source_ref_count=1)
        required=(("TASK_IDENTITY",discovered.task_identity),("SOURCE_SET_IDENTITY",discovered.source_set_identity),("DISCOVERY_IDENTITY",discovered.discovery_identity),("NORMALIZATION_IDENTITY",normalized.normalization_identity),("MR03_BINDING_IDENTITY",mr03.binding_identity),("MR04_BINDING_IDENTITY",mr04.binding_identity),("METRICS_IDENTITY",metric.metrics_identity))
        chain=provenance.ProvenanceChain(nodes=tuple(provenance.ProvenanceNode(name,value,f"fixture/{name.lower()}") for name,value in required),edges=())
        package=context_builder.build_context(discovered,normalized,(mr03,mr04),chain,metric,max_context_bytes=100000)
        return package,metric

    @staticmethod
    def _frozen_run(package,state="VERIFIED_PASS_FOR_REVIEW"):
        inputs=package.input_identities
        return evidence.build_frozen_run_record(task_identity=inputs["task_identity"],source_set_identity=inputs["source_set_identity"],discovery_identity=inputs["discovery_identity"],normalization_identity=inputs["normalization_identity"],mr03_result_identity="4"*64,mr04_result_identity="5"*64,byte_budget={"budget_identity":"c"*64,"max_raw_bytes":100000,"max_normalized_bytes":100000,"max_package_bytes":100000,"max_cloud_context_bytes":100000,"byte_budget_policy_version":"1.0.0","overflow_policy":"BLOCK_OR_DETERMINISTIC_REPACK","silent_truncation":False},state=state)

    @staticmethod
    def _cloud_budget(run):
        return {"budget_identity":run.byte_budget["budget_identity"],"max_cloud_context_bytes":run.byte_budget["max_cloud_context_bytes"],"overflow_policy":run.byte_budget["overflow_policy"],"silent_truncation":run.byte_budget["silent_truncation"]}

    @staticmethod
    def _token_metadata():
        return {"estimator_name":"non_whitespace_groups_div4","estimator_version":"1.0.0","input_bytes":0,"estimated_tokens":0,"confidence":"ADVISORY","authority":"ADVISORY_ONLY"}

    @classmethod
    def _cloud_context(cls,package,disclosure_record,run,**overrides):
        return cloud_boundary.admit_cloud_context(package,disclosure_record,run_identity=overrides.get("run_identity",run.run_identity),mr03_package_identity=overrides.get("mr03_package_identity",run.mr03_result_identity),mr04_result_identity=overrides.get("mr04_result_identity",run.mr04_result_identity),byte_budget=cls._cloud_budget(run),estimated_token_metadata=cls._token_metadata(),prohibited_assumptions=overrides.get("prohibited_assumptions",()),observational_metadata=overrides.get("observational_metadata"))

    @staticmethod
    def _request(cloud_context):
        return cloud_boundary.build_cloud_request(cloud_context,model_identifier="openai/gpt-5.6-luna",human_authorization_reference="human-auth:final-result-fixture")

    @staticmethod
    def _source_ref(cloud_context):
        return copy.deepcopy(dict(cloud_context.source_refs[0]))

    @classmethod
    def _proposal(cls,run,cloud_context,cloud_request,*,bound_package_identity="7"*64):
        ref=cls._source_ref(cloud_context)
        semantic={"schema_version":"1.0.0","request_identity":cloud_request.request_identity,"run_identity":run.run_identity,"task_identity":run.task_identity,"bound_mr03_package_identity":run.mr03_result_identity,"bound_mr04_result_identity":run.mr04_result_identity,"bound_context_identity":cloud_context.context_identity,"claims":[{"claim_id":"claim-001","claim_type":"FACT","claim_text_or_structured_value":{"value":"alpha"},"source_refs":[copy.deepcopy(ref)],"confidence_or_uncertainty":{"level":"HIGH","basis":"structured evidence"}}],"source_refs":[copy.deepcopy(ref)],"recommendation":{"kind":"SUMMARY","content":{"next":"review"}},"uncertainty":{"level":"LOW","items":[]},"escalation_flags":["HUMAN_REVIEW"]}
        proposal_identity=identity.sha256_canonical(semantic)
        record=copy.deepcopy(semantic); record.update({"proposal_id":proposal_identity,"proposal_identity":proposal_identity,"bound_package_identity":bound_package_identity,"proposer_metadata":{"model_identifier":"openai/gpt-5.6-luna","provider_request_id":"fixture-request","attempt_number":1,"usage_if_available":{"input_tokens":10}},"free_form_prose":"presentation only","observational_metadata":{}})
        return proposal.CloudProposal.from_mapping(record)

    @staticmethod
    def _proposal_with(proposal_record,**changes):
        row=proposal_record.to_dict(); row.update(copy.deepcopy(changes)); semantic={key:row[key] for key in proposal.PROPOSAL_IDENTITY_PREIMAGE}; proposal_identity=identity.sha256_canonical(semantic); row["proposal_id"]=proposal_identity; row["proposal_identity"]=proposal_identity
        return proposal.CloudProposal.from_mapping(row)

    @staticmethod
    def _verifier_failure(run,proposal_record):
        return Failure(schema_version="1.0.0",failure_code=FailureCode.MR05_PROPOSAL_UNSUPPORTED_CLAIM,failure_owner=FailureOwner.PROPOSAL_BINDING,severity=FailureSeverity.HIGH,state=FailureState.FAILED,run_identity=run.run_identity,related_identity=proposal_record.proposal_identity,message="claim cannot be tied to bounded evidence",human_escalation_required=False)

    @staticmethod
    def _legacy_result(package,metric,cloud_context,*,failure=None):
        inputs={"task_identity":cloud_context.task_identity,"source_set_identity":cloud_context.source_set_identity,"discovery_identity":package.input_identities["discovery_identity"],"normalization_identity":package.input_identities["normalization_identity"],"context_identity":cloud_context.context_identity}
        checks=[]
        for rule in verifier.RULE_CATALOG:
            if failure is not None and rule.rule_id == "CLAIM_SUPPORT": checks.append(verifier.build_verifier_check(rule_id=rule.rule_id,input_identity=cloud_context.context_identity,check_result="FAIL",failure_identity=failure.failure_identity,decision_reason_code=failure.failure_code.value))
            else: checks.append(verifier.build_verifier_check(rule_id=rule.rule_id,input_identity=cloud_context.context_identity,check_result="PASS"))
        return verifier.build_verifier_result(inputs,package.dependency_binding_identities,package.provenance_identity,metric.metrics_identity,verifier.FROZEN_CONTRACT_IDENTITIES,checks,() if failure is None else (failure,))

    @staticmethod
    def _legacy_with(legacy,**changes):
        row=legacy.to_dict(); row.update(copy.deepcopy(changes)); row["verifier_identity"]=None
        return verifier.VerifierResult.from_mapping(row)

    @classmethod
    def _public_verification(cls,proposal_record,cloud_context,*,failure=None):
        if failure is None:
            semantic={"schema_version":"1.0.0","proposal_identity":proposal_record.proposal_identity,"verification_result":"PASS_FOR_REVIEW","reason_codes":[],"reason_details":[],"verified_source_refs":[cls._source_ref(cloud_context)],"unsupported_claims":[],"missing_refs":[],"protected_content_findings":[],"identity_findings":[],"verification_policy_version":"1.0.0"}
        else:
            semantic={"schema_version":"1.0.0","proposal_identity":proposal_record.proposal_identity,"verification_result":"DENY","reason_codes":[failure.failure_code.value],"reason_details":[{"code":failure.failure_code.value,"owner":failure.failure_owner.value,"severity":failure.severity.value,"explanation":failure.message,"related_refs":[failure.related_identity]}],"verified_source_refs":[cls._source_ref(cloud_context)],"unsupported_claims":["claim-001"],"missing_refs":[],"protected_content_findings":[],"identity_findings":[],"verification_policy_version":"1.0.0"}
        record=dict(semantic); record["verification_identity"]=verifier.verification_identity_from_preimage(semantic)
        return verifier.VerificationRecord.from_mapping(record)

    @staticmethod
    def _verification_with(verification_record,**changes):
        row=verification_record.to_dict(); row.update(copy.deepcopy(changes)); row.pop("verification_identity",None); row.pop("observational_metadata",None); preimage={key:row[key] for key in verifier.VERIFICATION_RECORD_IDENTITY_PREIMAGE}; row["verification_identity"]=verifier.verification_identity_from_preimage(preimage)
        return verifier.VerificationRecord.from_mapping(row)

    @staticmethod
    def _gate(run,proposal_record,verification_record,**changes):
        fields={"run_identity":run.run_identity,"task_identity":proposal_record.task_identity,"proposal_identity":proposal_record.proposal_identity,"verification_identity":verification_record.verification_identity,"package_identity":proposal_record.bound_package_identity,"context_identity":proposal_record.bound_context_identity,"task_summary":"review task","proposal_summary":"review proposal","verification_result":verification_record.verification_result,"reason_codes":["VERIFIED"],"source_refs":[proposal_record.source_refs[0].to_dict()],"uncertainties":["none known"],"evidence_pointers":["evidence/manifest.json"]}; fields.update(changes)
        return human_gate.build_human_gate(**fields)

    @staticmethod
    def _decision(gate,decision="APPROVE"):
        return human_gate.build_human_decision(human_gate=gate,decision=decision,decision_reason="Reviewed exact evidence",decision_scope="This exact Human Gate only",human_authority_reference="human-auth:final-result-fixture")

    @staticmethod
    def _terminal_failure(run,proposal_record,related_identity=None):
        return Failure(schema_version="1.0.0",failure_code=FailureCode.MR05_MODEL_TIMEOUT,failure_owner=FailureOwner.MODEL_BOUNDARY,severity=FailureSeverity.HIGH,state=FailureState.FAILED,run_identity=run.run_identity,related_identity=proposal_record.proposal_identity if related_identity is None else related_identity,message="post-verification provider boundary failure fixture",human_escalation_required=True)

    @classmethod
    def _full_chain(cls,state="VERIFIED_PASS_FOR_REVIEW",*,verifier_deny=False):
        package,metric=cls._bounded_context_and_metrics(); run=cls._frozen_run(package,state); disc=disclosure.build_disclosure(classification="PUBLIC"); ctx=cls._cloud_context(package,disc,run); request=cls._request(ctx); prop=cls._proposal(run,ctx,request); vf=cls._verifier_failure(run,prop) if verifier_deny else None; legacy=cls._legacy_result(package,metric,ctx,failure=vf); verification=cls._public_verification(prop,ctx,failure=vf); gate=decision=None
        if state in {"HUMAN_APPROVED","HUMAN_REJECTED","HUMAN_REWORK","HUMAN_MORE_EVIDENCE"}:
            gate=cls._gate(run,prop,verification); decision=cls._decision(gate,{"HUMAN_APPROVED":"APPROVE","HUMAN_REJECTED":"REJECT","HUMAN_REWORK":"REQUEST_REWORK","HUMAN_MORE_EVIDENCE":"REQUEST_MORE_EVIDENCE"}[state])
        failure=cls._terminal_failure(run,prop) if state == "FAILED" else None
        return {"run":run,"bounded_context":package,"disclosure":disc,"cloud_context":ctx,"cloud_request":request,"proposal":prop,"metric":metric,"legacy":legacy,"verification":verification,"verifier_failures":() if vf is None else (vf,),"gate":gate,"decision":decision,"failure":failure}

    @staticmethod
    def _evidence_args(chain):
        return {"run_record":chain["run"],"bounded_context_record":chain["bounded_context"],"disclosure_record":chain["disclosure"],"cloud_context_record":chain["cloud_context"],"cloud_request_record":chain["cloud_request"],"proposal_record":chain["proposal"],"verification_record":chain["verification"],"metrics_record":chain["metric"],"legacy_verifier_result":chain["legacy"],"verifier_failure_records":chain["verifier_failures"],"human_gate_record":chain["gate"],"human_decision_record":chain["decision"],"failure_record":chain["failure"]}

    @classmethod
    def _manifest(cls,chain): return evidence.build_pre_final_evidence_manifest(**cls._evidence_args(chain))

    @classmethod
    def _final(cls,chain,manifest=None):
        if manifest is None: manifest=cls._manifest(chain)
        return evidence.build_final_result(terminal_state=chain["run"].state,manifest=manifest,**cls._evidence_args(chain))

    def test_frozen_run_identity_and_observations_are_deterministic(self):
        package,_=self._bounded_context_and_metrics(); first=self._frozen_run(package); second=evidence.build_frozen_run_record(task_identity=first.task_identity,source_set_identity=first.source_set_identity,discovery_identity=first.discovery_identity,normalization_identity=first.normalization_identity,mr03_result_identity=first.mr03_result_identity,mr04_result_identity=first.mr04_result_identity,byte_budget=dict(first.byte_budget),state="HUMAN_APPROVED",observational_metadata={"ratio":0.5})
        self.assertEqual(first.run_identity,second.run_identity); self.assertNotEqual(first.canonical_bytes(),second.canonical_bytes())

    def test_pre_final_manifest_binds_all_authoritative_dependencies(self):
        chain=self._full_chain(); manifest=self._manifest(chain); paths=[x.relative_path for x in manifest.artifacts]
        for required in ("cloud/context.json","cloud/request.json","context/bounded_context.json","disclosure/disclosure.json","metrics/metrics.json","proposal/proposal.json","run/run.json","verification/legacy_verifier.json","verification/verification.json"): self.assertIn(required,paths)
        self.assertEqual(paths,sorted(paths)); self.assertFalse(any(x.artifact_type=="mr05.final_result" for x in manifest.artifacts))

    def test_valid_exact_full_authoritative_chain_passes(self):
        chain=self._full_chain(); manifest=self._manifest(chain); result=self._final(chain,manifest)
        self.assertEqual(result.terminal_state,"VERIFIED_PASS_FOR_REVIEW"); self.assertEqual(result.metrics_identity,chain["metric"].metrics_identity); self.assertEqual(result.final_result_identity,identity.sha256_canonical(result.identity_payload()))
        canonical=evidence.canonical_final_result_bytes(result,manifest=manifest,**self._evidence_args(chain)); self.assertEqual(canonical,canonical_json_bytes(result.to_dict(),identity_critical=False))

    def test_human_approved_chain_passes_and_preserves_gate_binding(self):
        chain=self._full_chain("HUMAN_APPROVED"); result=self._final(chain); self.assertEqual(result.human_decision_if_any,"APPROVE"); self.assertEqual(chain["gate"].package_identity,chain["proposal"].bound_package_identity)

    def test_failed_chain_requires_bound_terminal_failure(self):
        chain=self._full_chain("FAILED"); result=self._final(chain); self.assertEqual(result.failure_if_any,chain["failure"].failure_identity); chain["failure"]=self._terminal_failure(chain["run"],chain["proposal"],"f"*64)
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_missing_authoritative_dependency_fails_closed(self):
        chain=self._full_chain(); args=self._evidence_args(chain); args["bounded_context_record"]=None
        with self.assertRaises(evidence.EvidenceValidationError): evidence.build_pre_final_evidence_manifest(**args)

    def test_raw_identity_substitution_for_authoritative_dependency_fails_closed(self):
        chain=self._full_chain(); args=self._evidence_args(chain); args["cloud_request_record"]=chain["cloud_request"].request_identity
        with self.assertRaises(evidence.EvidenceValidationError): evidence.build_pre_final_evidence_manifest(**args)

    def test_unrelated_metrics_fails_closed(self):
        chain=self._full_chain(); chain["metric"]=metrics.Metrics(raw_source_bytes=999,normalized_bytes=500,package_bytes=400,cloud_context_bytes=100)
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_metrics_not_bound_to_legacy_verifier_fails_closed(self):
        chain=self._full_chain(); old=chain["legacy"]
        chain["legacy"]=verifier.VerifierResult(schema_id=old.schema_id,schema_version=old.schema_version,verification_policy_version=old.verification_policy_version,input_identities=old.input_identities,dependency_binding_identities=old.dependency_binding_identities,provenance_identity=old.provenance_identity,metrics_identity="f"*64,contract_identities=old.contract_identities,rule_identities=old.rule_identities,checks=old.checks,missing_rule_ids=old.missing_rule_ids,failure_identities=old.failure_identities,decision=old.decision,decision_reason_code=old.decision_reason_code)
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_legacy_discovery_identity_mismatch_fails_closed(self):
        chain=self._full_chain(); inputs=dict(chain["legacy"].input_identities); inputs["discovery_identity"]="e"*64; chain["legacy"]=self._legacy_with(chain["legacy"],input_identities=inputs)
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_legacy_normalization_identity_mismatch_fails_closed(self):
        chain=self._full_chain(); inputs=dict(chain["legacy"].input_identities); inputs["normalization_identity"]="e"*64; chain["legacy"]=self._legacy_with(chain["legacy"],input_identities=inputs)
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_legacy_dependency_bindings_mismatch_fails_closed(self):
        chain=self._full_chain(); chain["legacy"]=self._legacy_with(chain["legacy"],dependency_binding_identities=("0"*64,"1"*64))
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_legacy_provenance_identity_mismatch_fails_closed(self):
        chain=self._full_chain(); chain["legacy"]=self._legacy_with(chain["legacy"],provenance_identity="e"*64)
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_legacy_task_source_set_and_context_mismatches_remain_fail_closed(self):
        base=self._full_chain()
        for field in ("task_identity","source_set_identity","context_identity"):
            with self.subTest(field=field):
                chain=dict(base); inputs=dict(base["legacy"].input_identities); inputs[field]="e"*64; chain["legacy"]=self._legacy_with(base["legacy"],input_identities=inputs)
                with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_extra_unreferenced_verifier_failure_fails_closed(self):
        chain=self._full_chain(); chain["verifier_failures"]=(self._verifier_failure(chain["run"],chain["proposal"]),)
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_duplicate_verifier_failure_fails_closed(self):
        chain=self._full_chain("VERIFIED_DENY",verifier_deny=True); failure=chain["verifier_failures"][0]; chain["verifier_failures"]=(failure,failure)
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_nonempty_failure_set_for_pass_verifier_fails_closed(self):
        chain=self._full_chain(); extra=self._verifier_failure(chain["run"],chain["proposal"]); self.assertEqual(chain["legacy"].failure_identities,()); chain["verifier_failures"]=(extra,)
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_verifier_failure_run_identity_mismatch_fails_closed(self):
        chain=self._full_chain("VERIFIED_DENY")
        bad=Failure(schema_version="1.0.0",failure_code=FailureCode.MR05_PROPOSAL_UNSUPPORTED_CLAIM,failure_owner=FailureOwner.PROPOSAL_BINDING,severity=FailureSeverity.HIGH,state=FailureState.FAILED,run_identity="e"*64,related_identity=chain["proposal"].proposal_identity,message="wrong-run verifier failure",human_escalation_required=False)
        chain["legacy"]=self._legacy_result(chain["bounded_context"],chain["metric"],chain["cloud_context"],failure=bad); chain["verification"]=self._public_verification(chain["proposal"],chain["cloud_context"],failure=bad); chain["verifier_failures"]=(bad,)
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_valid_pass_chain_with_exact_empty_failure_set_passes(self):
        chain=self._full_chain(); self.assertEqual(chain["legacy"].failure_identities,()); self.assertEqual(chain["verifier_failures"],()); self._final(chain)

    def test_valid_nonpass_chain_with_exact_required_failure_set_passes(self):
        chain=self._full_chain("VERIFIED_DENY",verifier_deny=True); self.assertEqual(tuple(x.failure_identity for x in chain["verifier_failures"]),chain["legacy"].failure_identities); result=self._final(chain); self.assertEqual(result.verification_result,"DENY")

    def test_required_verifier_failure_manifest_member_tamper_fails_closed(self):
        chain=self._full_chain("VERIFIED_DENY",verifier_deny=True); manifest=self._manifest(chain); target=f"verification/failures/{chain['verifier_failures'][0].failure_identity}.json"; altered=[]
        for item in manifest.artifacts:
            row=item.to_dict()
            if row["relative_path"]==target: row["sha256"]="0"*64
            altered.append(evidence.FrozenEvidenceArtifact.from_mapping(row))
        tampered=evidence.FrozenEvidenceManifest(run_identity=manifest.run_identity,artifacts=tuple(altered))
        with self.assertRaises(evidence.EvidenceValidationError): self._final(chain,tampered)

    def test_required_verifier_failure_manifest_member_missing_fails_closed(self):
        chain=self._full_chain("VERIFIED_DENY",verifier_deny=True); manifest=self._manifest(chain); target=f"verification/failures/{chain['verifier_failures'][0].failure_identity}.json"; reduced=evidence.FrozenEvidenceManifest(run_identity=manifest.run_identity,artifacts=tuple(x for x in manifest.artifacts if x.relative_path!=target))
        with self.assertRaises(evidence.EvidenceValidationError): self._final(chain,reduced)

    def test_fabricated_request_identity_fails_closed(self):
        chain=self._full_chain(); chain["proposal"]=self._proposal_with(chain["proposal"],request_identity="e"*64); chain["verification"]=self._public_verification(chain["proposal"],chain["cloud_context"])
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_request_context_mismatch_fails_closed(self):
        chain=self._full_chain(); alt=self._cloud_context(chain["bounded_context"],chain["disclosure"],chain["run"],prohibited_assumptions=("alternate",)); chain["cloud_request"]=self._request(alt)
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_request_run_mismatch_fails_closed(self):
        chain=self._full_chain(); alt=self._cloud_context(chain["bounded_context"],chain["disclosure"],chain["run"],run_identity="e"*64); chain["cloud_request"]=self._request(alt)
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_fabricated_context_identity_fails_closed(self):
        chain=self._full_chain(); chain["proposal"]=self._proposal_with(chain["proposal"],bound_context_identity="d"*64); chain["verification"]=self._public_verification(chain["proposal"],chain["cloud_context"])
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_context_run_mismatch_fails_closed(self):
        chain=self._full_chain(); chain["cloud_context"]=self._cloud_context(chain["bounded_context"],chain["disclosure"],chain["run"],run_identity="e"*64); chain["cloud_request"]=self._request(chain["cloud_context"])
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_context_task_mismatch_fails_closed(self):
        chain=self._full_chain(); alt,_=self._bounded_context_and_metrics(task_id="alternate-task"); chain["cloud_context"]=self._cloud_context(alt,chain["disclosure"],chain["run"]); chain["cloud_request"]=self._request(chain["cloud_context"])
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_context_source_set_mismatch_fails_closed(self):
        chain=self._full_chain(); alt,_=self._bounded_context_and_metrics(raw=b'{"cloud":2}',locator="alternate.json"); chain["cloud_context"]=self._cloud_context(alt,chain["disclosure"],chain["run"]); chain["cloud_request"]=self._request(chain["cloud_context"])
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_context_mr03_mismatch_fails_closed(self):
        chain=self._full_chain(); chain["cloud_context"]=self._cloud_context(chain["bounded_context"],chain["disclosure"],chain["run"],mr03_package_identity="d"*64); chain["cloud_request"]=self._request(chain["cloud_context"])
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_context_mr04_mismatch_fails_closed(self):
        chain=self._full_chain(); chain["cloud_context"]=self._cloud_context(chain["bounded_context"],chain["disclosure"],chain["run"],mr04_result_identity="d"*64); chain["cloud_request"]=self._request(chain["cloud_context"])
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_public_verification_not_authoritative_adapter_qualified_fails_closed(self):
        chain=self._full_chain(); chain["verification"]=self._verification_with(chain["verification"],verified_source_refs=[])
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_legacy_verifier_decision_mismatch_fails_closed(self):
        chain=self._full_chain(); failure=self._verifier_failure(chain["run"],chain["proposal"]); chain["legacy"]=self._legacy_result(chain["bounded_context"],chain["metric"],chain["cloud_context"],failure=failure); chain["verifier_failures"]=(failure,)
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_fabricated_verification_source_ref_fails_closed(self):
        chain=self._full_chain(); fake=self._source_ref(chain["cloud_context"]); fake["source_id"]="f"*64; chain["verification"]=self._verification_with(chain["verification"],verified_source_refs=[fake])
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_missing_verifier_failure_evidence_fails_closed(self):
        chain=self._full_chain("VERIFIED_DENY",verifier_deny=True); chain["verifier_failures"]=()
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_required_authoritative_manifest_member_tamper_fails_closed(self):
        chain=self._full_chain(); manifest=self._manifest(chain); altered=[]
        for item in manifest.artifacts:
            row=item.to_dict()
            if row["relative_path"]=="cloud/request.json": row["sha256"]="0"*64
            altered.append(evidence.FrozenEvidenceArtifact.from_mapping(row))
        tampered=evidence.FrozenEvidenceManifest(run_identity=manifest.run_identity,artifacts=tuple(altered))
        with self.assertRaises(evidence.EvidenceValidationError): self._final(chain,tampered)

    def test_required_authoritative_manifest_member_missing_fails_closed(self):
        chain=self._full_chain(); manifest=self._manifest(chain); reduced=evidence.FrozenEvidenceManifest(run_identity=manifest.run_identity,artifacts=tuple(x for x in manifest.artifacts if x.relative_path!="verification/legacy_verifier.json"))
        with self.assertRaises(evidence.EvidenceValidationError): self._final(chain,reduced)

    def test_bound_package_identity_remains_identity_excluded_per_frozen_contract(self):
        chain=self._full_chain(); original=chain["proposal"]; changed=self._proposal_with(original,bound_package_identity="f"*64); self.assertNotIn("bound_package_identity",proposal.PROPOSAL_IDENTITY_PREIMAGE); self.assertIn("bound_package_identity",proposal.PROPOSAL_IDENTITY_EXCLUSIONS); self.assertEqual(original.proposal_identity,changed.proposal_identity); gate=self._gate(chain["run"],changed,chain["verification"]); self.assertEqual(gate.package_identity,changed.bound_package_identity)

    def test_proposal_run_task_mr03_mr04_bindings_remain_fail_closed(self):
        chain=self._full_chain()
        for changes in ({"run_identity":"9"*64},{"task_identity":"9"*64},{"bound_mr03_package_identity":"9"*64},{"bound_mr04_result_identity":"9"*64}):
            with self.subTest(changes=changes):
                local=dict(chain); local["proposal"]=self._proposal_with(chain["proposal"],**changes); local["verification"]=self._public_verification(local["proposal"],chain["cloud_context"])
                with self.assertRaises(evidence.EvidenceValidationError): self._manifest(local)

    def test_human_gate_cross_record_bindings_remain_fail_closed(self):
        chain=self._full_chain("HUMAN_APPROVED"); gate=self._gate(chain["run"],chain["proposal"],chain["verification"],context_identity="9"*64); chain["gate"]=gate; chain["decision"]=self._decision(gate)
        with self.assertRaises(evidence.EvidenceValidationError): self._manifest(chain)

    def test_noncanonical_manifest_paths_remain_fail_closed(self):
        invalid=("/a",r"a\b","a//b","a/./b","a/../b","a/","C:foo","a\x00b","a\nb","a\rb")
        for path in invalid:
            with self.subTest(path=repr(path)),self.assertRaises(evidence.EvidenceValidationError): evidence.FrozenEvidenceArtifact(path,1,"b"*64,"fixture","1.0.0")

    def test_run_state_must_match_terminal_state(self):
        chain=self._full_chain(); manifest=self._manifest(chain)
        with self.assertRaises(evidence.EvidenceValidationError): evidence.build_final_result(terminal_state="HUMAN_APPROVED",manifest=manifest,**self._evidence_args(chain))

    def test_final_result_artifact_is_forbidden_from_pre_final_manifest(self):
        with self.assertRaises(evidence.EvidenceValidationError): evidence.FrozenEvidenceManifest(run_identity="a"*64,artifacts=(evidence.FrozenEvidenceArtifact("final/result.json",1,"b"*64,"mr05.final_result","1.0.0"),))

    def test_final_result_has_zero_execution_authority(self):
        names=("FINAL_RESULT_EXECUTION_COUNT","FINAL_RESULT_HUMAN_APPROVAL_EXECUTION_COUNT","FINAL_RESULT_STATE_TRANSITION_EXECUTION_COUNT","FINAL_RESULT_NETWORK_IMPLEMENTATION_COUNT","FINAL_RESULT_PROVIDER_CLIENT_IMPLEMENTATION_COUNT","FINAL_RESULT_MODEL_CALL_IMPLEMENTATION_COUNT","FINAL_RESULT_AUTH_IMPLEMENTATION_COUNT","FINAL_RESULT_GIT_OPERATION_COUNT")
        self.assertEqual(evidence.FINAL_RESULT_IMPLEMENTATION_COUNT,1); self.assertTrue(all(getattr(evidence,name)==0 for name in names))


if __name__ == "__main__":
    unittest.main()
