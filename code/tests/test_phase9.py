"""Independent positive and adversarial proofs for the bounded document rescue."""
from dataclasses import replace
import unittest
from _support import ROOT
import test_phase5
from test_phase5 import pipeline, case
from test_evidence_index import json_result, record
from test_evidence_adapters import moment
from ghost_audit.documents import validated_ocr_observations
from ghost_audit.evidence import EvidenceIndex
from ghost_audit.pipeline import AuditPipeline
from ghost_audit.timeline import StateEngine


def ticket_screen(email="new@example.test", order_x=1441, day=2):
    doc=test_phase5.Phase5Tests.visual([("Helpline Console",245,23),("support-fixture",247,138),
                           ("Email",645,234),(email,645,254),("Conversation",261,333),
                           ("Order ORD-FIXTURE",order_x,333)])
    # A literal source resource token, unrelated to public resource identifiers.
    regions=tuple(replace_region(r) for r in doc.regions)
    return replace(doc,source=replace(doc.source,origin="support_platform",available_at=moment(day)),
                   raw_text=doc.raw_text.replace("support-fixture","support_fixture"),regions=regions)


def replace_region(region):
    from ghost_audit.normalization import freeze
    value=dict(region)
    value['text']=value['text'].replace('support-fixture','support_fixture')
    value['words']=[{**dict(w),'text':w['text'].replace('support-fixture','support_fixture')} for w in value['words']]
    return freeze(value)


class Phase9DocumentTests(unittest.TestCase):
    def test_explicit_delivery_query_context_is_redacted_not_deleted(self):
        record={'resource_id':'delivery-ticket-fixture','system_id':'support_platform','record_type':'SUPPORT_MESSAGE',
                'message_excerpt':'Customer supplied contact details for a delivery query.',
                'observed_at':moment(2).isoformat(),
                'customer_reference':'subject-a','requester_name':None,'requester_phone':None,
                'requester_email':'new@example.test'}
        for reference in ('subject-a',None):
            record['customer_reference']=reference
            p=pipeline([json_result({'service_exports':{'support_platform':{'tickets':[record]}}})])
            out=p.audit(replace(case(),request_text='Delete my personal data.'))
            self.assertEqual(out.result.deletion_status,'INCOMPLETE')
            decision=next(d for d in out.decisions if d.resource.resource_id=='delivery-ticket-fixture')
            self.assertTrue(decision.condition_proofs)
            self.assertEqual(decision.remediation,'REDACT_RECORD')
            self.assertFalse(any(s.operation=='DELETE_RECORD' for s in out.result.steps))

    def test_contact_details_without_fulfillment_context_stay_unknown(self):
        from test_phase4 import fixture, profile
        record={'resource_id':'contact-ticket-fixture','system_id':'support_platform','record_type':'SUPPORT_MESSAGE',
                'message_excerpt':'Customer supplied contact details.','requester_email':'new@example.test'}
        out,p,request=fixture([profile(result='NOT_FOUND'),record])
        self.assertIsNone(out.result)
        d=next(d for d in out.decisions if d.resource.resource_id=='contact-ticket-fixture')
        self.assertEqual(d.reason,'unsupported_or_unknown_rule_condition')
        self.assertIsNone(d.verification)

    def test_isolated_future_checks_do_not_bypass_unknown_policy_or_plan_contract(self):
        import json
        from evaluation.phase9_obligations import candidate_row, classify_obligation
        from test_phase4 import fixture, profile
        from ghost_audit.output import validate_steps_contract
        out,p,request=fixture([profile(result='NOT_FOUND'),
                             {'resource_id':'retention-fixture','system_id':'security_service','record_type':'SECURITY_AUDIT_LOG'}])
        self.assertIsNone(out.result)
        row,entries=candidate_row(out,request,p.index)
        self.assertEqual(row['deletion_status'],'INCOMPLETE')
        self.assertEqual(len(json.loads(row['steps_json'])),1)
        self.assertEqual(json.loads(row['steps_json'])[0]['evidence_id'],'')
        with self.assertRaises(ValueError):
            validate_steps_contract(row['deletion_status'],json.loads(row['steps_json']))
        known=[d for d in out.decisions if d.verification]
        changed=replace(out,report=replace(out.report,user_id='different-subject'))
        self.assertEqual(classify_obligation(known,changed,request,p.index),'c_ambiguous_subject')
        proof=known[0].proofs[0]
        modified=replace(known[0],proofs=(replace(proof,source=replace(proof.source,available_at=moment(20))),))
        self.assertEqual(classify_obligation([modified],out,request,p.index),'e_temporally_invalid')

    def test_selected_ticket_order_context_drives_existing_redact_rule(self):
        result=json_result(record('support_fixture',system_id='support_platform',record_type='SUPPORT_MESSAGE',email='new@example.test'))
        original=pipeline([result])
        self.assertFalse(validated_ocr_observations((ticket_screen(),),original.index))
        observations=validated_ocr_observations((ticket_screen(),),original.index,enable_support_context=True)
        self.assertEqual(len(observations),1)
        self.assertTrue(observations[0].attributes['shared_context'])
        self.assertEqual(len(observations[0].context['ocr_regions']),4)
        augmented=replace(result,observations=(*result.observations,*observations))
        p=pipeline([augmented]);out=p.audit(replace(case(),request_text='Delete my personal data.'))
        self.assertTrue(any(d.rule and d.rule.rule_id=='rule_05' and d.compliant is False for d in out.decisions))
        self.assertTrue(any(s.operation=='REDACT_RECORD' for s in out.result.steps))
        self.assertFalse(any(s.operation=='DELETE_RECORD' for s in out.result.steps))

    def test_other_row_order_and_wrong_source_do_not_supply_context(self):
        p=pipeline([json_result(record('support_fixture',system_id='support_platform',record_type='SUPPORT_MESSAGE'))])
        self.assertFalse(validated_ocr_observations((ticket_screen(order_x=600),),p.index,enable_support_context=True))
        doc=ticket_screen();doc=replace(doc,source=replace(doc.source,origin='unrelated_service'))
        self.assertFalse(validated_ocr_observations((doc,),p.index,enable_support_context=True))

    def test_future_capture_and_other_visible_owner_are_not_assigned(self):
        result=json_result(record('support_fixture',system_id='support_platform',record_type='SUPPORT_MESSAGE',email='new@example.test'))
        original=pipeline([result])
        for doc in (ticket_screen(day=6),ticket_screen(email='another@example.test')):
            observations=validated_ocr_observations((doc,),original.index,enable_support_context=True)
            augmented=replace(result,observations=(*result.observations,*observations))
            out=pipeline([augmented]).audit(replace(case(),request_text='Delete my personal data.'))
            self.assertFalse(any(d.rule and d.rule.rule_id=='rule_05' and d.compliant is False for d in out.decisions))


if __name__=='__main__':
    unittest.main()
