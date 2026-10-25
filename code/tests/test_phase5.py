"""Independent regression fixtures for source-grounded recall improvements."""
from dataclasses import replace
import unittest

from _support import DATASET
from test_evidence_adapters import extract, moment, source
from test_evidence_index import json_result, record
from test_identity import snapshot, change
from test_state import case as factual_case
from ghost_audit.evidence import EvidenceIndex
from ghost_audit.identity import IdentityIndex
from ghost_audit.io import DatasetReader
from ghost_audit.pipeline import AuditPipeline
from ghost_audit.documents import candidates, validated_ocr_observations
from ghost_audit.models import VisualDocument
from ghost_audit.normalization import freeze
from ghost_audit.state_facts import category, logical_system, normalize_facts, physical_scope
from ghost_audit.timeline import StateEngine


def pipeline(results, identity=None):
    identity = identity or IdentityIndex([snapshot()], [change()])
    index = EvidenceIndex(results, identity_index=identity)
    return AuditPipeline(StateEngine(index), DatasetReader().rules())


def case(*args, **kwargs):
    return replace(factual_case(*args, **kwargs), request_text="Please delete my account and personal data.")


class Phase5Tests(unittest.TestCase):
    def test_null_log_payload_is_cleared_but_raw_tokens_survive(self):
        result = extract('.log', '2025-01-02T00:00:00Z service=analytics_platform event=analytics_profile_read_completed resource_id=ar customer_reference=null email=null phone=null email_hash=null')
        o = result.observations[0]
        self.assertIsNone(o.attributes['email'])
        self.assertEqual(o.raw_fields['email'], 'null')
        self.assertFalse(o.identifiers)
        facts, _ = normalize_facts(o)
        self.assertIn(('direct_identifier:email','CLEARED'), {(f.dimension,f.value) for f in facts})
        self.assertNotIn(('identifiability','IDENTIFIABLE'), {(f.dimension,f.value) for f in facts})
        cloud=extract('.log','2025-01-02T00:00:00Z function=analytics_platform requestId=alpha message="event=analytics_profile_read resource_id=ar email=null phone=null direct_identifiers=0"').observations[0]
        self.assertIsNone(cloud.attributes['message_fields']['email'])
        self.assertEqual(cloud.raw_fields['message_fields']['email'],'null')
        self.assertFalse(cloud.identifiers)
        native=extract('.log','2025-01-02T00:00:00Z {"event":"analytics_profile_read","resource_id":"ar","email":"null"}').observations[0]
        self.assertEqual(native.attributes['email'],'null')

    def test_historical_trace_completion_404_is_linked_to_correct_person(self):
        result = extract('.log', '\n'.join([
            '2025-01-02T00:00:00Z service=account_service event=profile_lookup_started trace_id=alpha lookup_key=old@example.test',
            '2025-01-02T00:00:01Z service=account_service event=profile_lookup_completed trace_id=alpha resource_id=profile-a rows=0 http_status=404 customer_reference=null',
            '2025-01-02T00:00:01Z service=account_service event=profile_lookup_completed trace_id=beta resource_id=other rows=1 http_status=200 email=decoy@example.test']))
        out = pipeline([result]).audit(case())
        self.assertEqual(out.result.deletion_status, 'COMPLETE')
        self.assertEqual([s.resource_id for s in out.result.steps], ['profile-a'])
        self.assertEqual(out.result.steps[0].evidence_id, 'fixture')

    def test_duplicate_trace_subject_anchors_do_not_claim_anonymous_completion(self):
        result = extract('.log', '\n'.join([
            '2025-01-02T00:00:00Z service=account_service event=profile_lookup_started trace_id=duplicate lookup_key=new@example.test',
            '2025-01-02T00:00:00Z service=account_service event=profile_lookup_started trace_id=duplicate lookup_key=other@example.test',
            '2025-01-02T00:00:01Z service=account_service event=profile_lookup_completed trace_id=duplicate resource_id=ambiguous rows=0 http_status=404']))
        identity = IdentityIndex([snapshot(), snapshot('second','other@example.test',phone='second-phone',email_hash='second-hash')],[])
        p = pipeline([result], identity)
        out = p.audit(case())
        self.assertIsNone(out.result)
        self.assertFalse(any(r.resource_id == 'ambiguous' for r in out.report.resources))

    def test_late_captured_trace_cannot_prove_early_absence(self):
        result = extract('.log', '\n'.join([
            '2025-01-02T00:00:00Z service=account_service event=profile_lookup_started trace_id=a lookup_key=new@example.test',
            '2025-01-02T00:00:01Z service=account_service event=profile_lookup_completed trace_id=a resource_id=profile-a rows=0 http_status=404']),source('late',6))
        self.assertIsNone(pipeline([result]).audit(case()).result)

    def test_contact_replica_schema_preserves_actual_system_and_component(self):
        result = extract('.log', '\n'.join([
            '2025-01-02T00:00:00Z service=support_replica event=contact_query_started trace_id=c lookup_key=new@example.test',
            '2025-01-02T00:00:01Z service=support_replica event=contact_query_completed trace_id=c resource_id=arbitrary-prefix rows=1']),
            replace(source(), origin='support_platform'))
        observation = result.observations[1]
        self.assertEqual(category(observation), 'SECONDARY_IDENTIFIER')
        self.assertEqual(logical_system(observation), 'support_platform')
        self.assertEqual(physical_scope(observation).topology, 'service:support_replica')
        out = pipeline([result]).audit(replace(case(), request_text='Remove my personal information.'))
        self.assertEqual([s.operation for s in out.result.steps], ['REPORT_REMAINING_RECORD','DELETE_RECORD','VERIFY_RECORD_ABSENT'])
        self.assertEqual(out.result.steps[0].system_id, 'support_platform')

    def test_contact_lookup_not_analytics_policy_from_resource_prefix(self):
        result = extract('.log','2025-01-02T00:00:00Z service=analytics_platform event=contact_lookup_completed resource_id=analytics-fixture rows=1 lookup_key=new@example.test email_opt_in=true')
        self.assertEqual(category(result.observations[0]), 'SECONDARY_IDENTIFIER')
        out = pipeline([result]).audit(replace(case(), request_text='Remove my personal information.'))
        self.assertEqual(out.result.steps[1].operation, 'DELETE_RECORD')

    def test_heartbeat_observes_enabled_flag_not_last_run_result(self):
        for flag,expected in [('true','ACTIVE'),('false','DISABLED')]:
            result = extract('.log', f'2025-01-02T00:00:00Z service=integration_service event=connector_heartbeat resource_id=flow-fixture enabled={flag} scheduler_registered=true last_run=success lookup_key=new@example.test')
            report = pipeline([result]).state_engine.reconstruct_case(case())
            self.assertEqual(report.resources[0].data_flow,expected)
            self.assertEqual(report.resources[0].recreation,())

    def test_snapshot_declared_identity_store_is_not_account_service(self):
        result = json_result({'captured_at':'2025-01-02T00:00:00Z','snapshots':[{'data_store':'identity_service','collection':'deleted_customer_references','records':[{'resource_id':'ts','subject_reference':'user_fixture','email_hash':'hash'}]}]})
        self.assertEqual(logical_system(result.observations[0]), 'identity_service')
        self.assertEqual(category(result.observations[0]), 'ACCOUNT_TOMBSTONE')

    def test_explicit_analytics_attribution_slots_clear_without_fictional_flag(self):
        result = json_result(record('aggregate',system_id='analytics_platform',record_type='ANALYTICS_PROFILE',
                                    customer_reference=None,email=None,phone=None,email_hash=None,
                                    query={'email':'new@example.test'},audience_cohort='general',logger='analytics-readback',severity='INFO',seq=42))
        out = pipeline([result]).audit(replace(case(),request_text='Remove my personal information.'))
        self.assertEqual(out.result.deletion_status,'COMPLETE')
        self.assertEqual(out.result.steps[0].operation,'VERIFY_RECORD_ANONYMIZED')

    def test_null_email_or_surviving_device_key_does_not_prove_anonymity(self):
        for values in ({'email':None}, {'customer_reference':None,'email':None,'phone':None,'email_hash':None,'device_id':'still-linked'},
                       {'customer_reference':None,'email':None,'phone':None,'email_hash':None,'ip_address':'192.0.2.1'},
                       {'customer_reference':None,'email':None,'phone':None,'email_hash':None,'metrics':{'customer_reference':'opaque-owner'}}):
            result = json_result(record('aggregate',system_id='analytics_platform',record_type='ANALYTICS_PROFILE',
                                        query={'email':'new@example.test'},**values))
            facts,_ = normalize_facts(result.observations[0])
            self.assertFalse(any(f.dimension=='identifiability' and f.value=='ANONYMIZED' for f in facts))

    def test_reference_registry_schema_supplies_purpose_but_not_missing_clearance(self):
        def artifact(**fields):
            return json_result({'captured_at':'2025-01-02T00:00:00Z','snapshots':[{'data_store':'identity_service',
                               'collection':'deleted_customer_references','records':[{'resource_id':'reference',
                               'subject_reference':'user_fixture','account_status':'DELETED',**fields}]}]})
        identity=IdentityIndex([snapshot('user_fixture')],[])
        out=pipeline([artifact(name=None,email=None,phone=None,email_hash='surviving-hash')],identity).audit(replace(case(),request_text='Remove my personal information.'))
        self.assertEqual(out.result.deletion_status,'INCOMPLETE')
        self.assertEqual(out.result.steps[0].operation,'REPORT_EXPOSED_PII')
        self.assertFalse(any(s.operation=='DELETE_RECORD' for s in out.result.steps))
        out=pipeline([artifact(name=None,email=None,phone=None,email_hash=None)],identity).audit(replace(case(),request_text='Remove my personal information.'))
        self.assertEqual(out.result.deletion_status,'COMPLETE')
        self.assertEqual(out.result.steps[0].operation,'VERIFY_RECORD_REDACTED')
        blocked=pipeline([artifact(name=None,email=None,phone=None,email_hash=None,references_required=False)],identity).audit(replace(case(),request_text='Remove my personal information.'))
        self.assertIsNone(blocked.result)

    def test_declared_sql_support_schema_clearance_preserves_shared_order_context(self):
        sql="""-- Captured at: 2025-01-02T00:00:00Z
CREATE TABLE support_records(resource_id TEXT,customer_reference TEXT,requester_name TEXT,requester_email TEXT,requester_phone TEXT,message_excerpt TEXT);
INSERT INTO support_records VALUES('ticket','subject-a',NULL,NULL,NULL,'Customer followed up about an order update.');"""
        out=pipeline([extract('.sql',sql)]).audit(replace(case(),request_text='Remove my personal information.'))
        self.assertEqual(out.result.deletion_status,'COMPLETE')
        self.assertEqual(out.result.steps[0].operation,'VERIFY_RECORD_REDACTED')

    def test_unknown_owner_on_colliding_resource_is_not_invented_alias(self):
        known=json_result(record('same',system_id='account_service',record_type='USER_PROFILE',email='new@example.test'), 'known')
        other=json_result(record('same',system_id='account_service',record_type='USER_PROFILE',email='unregistered@example.test'),'other')
        out=pipeline([known,other]).audit(case())
        self.assertTrue(any(g.code=='unresolved_resource_owner' for g in out.blockers))
        self.assertFalse(any(o.source.evidence_id=='other' for r in out.report.resources for o in r.observations))

    def test_grouped_recall_preserves_original_step_accounting(self):
        from evaluation.metrics import score_predictions
        step={'step_no':1,'phase':'VERIFICATION','operation':'VERIFY_RECORD_ABSENT','system_id':'a','resource_id':'r','state':'ABSENT','evidence_id':'e'}
        row={'case_id':'synthetic','deletion_status':'COMPLETE','steps':[step]}
        metrics=score_predictions([row],[row])
        self.assertEqual(metrics['steps']['true_positive'],1)
        for field,key in [('phase','VERIFICATION'),('operation','VERIFY_RECORD_ABSENT'),('system_id','a')]:
            self.assertEqual(metrics['grouped_steps'][field][key]['recall'],1)

    @staticmethod
    def visual(lines):
        text=' '.join(line for line,x,y in lines)
        regions=tuple(freeze({'text':line,'words':[{'text':line,'x':x,'y':y,'width':100,'height':14}]}) for line,x,y in lines)
        return VisualDocument(replace(source('visual'),locator='image:full',file_path='evidence/fixture.png'),
                              'text_extracted',text,regions,candidates(text,'image:full'),(),None,True,'Windows.Media.Ocr',())

    def test_located_ocr_connector_uses_configuration_and_actual_clock(self):
        doc=self.visual([('BridgeOps',250,20),('PRODUCTION eu-west 02 Jan 2025 08:00 UTC',250,140),
                         ('data_flow_fixture',1440,333),('Selector',1440,478),('new@example.test',1556,479),
                         ('Sync mode',1440,510),('Continuous Sync',1556,511)])
        result=json_result(record('data_flow_fixture',system_id='integration_service',record_type='DATA_FLOW',subject_selector='new@example.test'))
        index=pipeline([result]).index
        observations=validated_ocr_observations((doc,),index)
        self.assertEqual(len(observations),1)
        o=observations[0]
        self.assertEqual(o.observed_at.hour,8)
        self.assertTrue(o.attributes['enabled'])
        self.assertIn('/regions:',o.source.locator)
        self.assertEqual(len(o.context['ocr_regions']),4)
        broken=replace(doc,regions=(),raw_text=doc.raw_text)
        self.assertFalse(validated_ocr_observations((broken,),index))

    def test_ocr_corroborration_clock_cannot_leak_future_id_link(self):
        from ghost_audit.state_facts import temporal_rejection
        doc=self.visual([('BridgeOps',250,20),('PRODUCTION eu-west 02 Jan 2025 08:00 UTC',250,140),
                         ('data_flow_fixture',1440,333),('Selector',1440,478),('new@example.test',1556,479),
                         ('Sync mode',1440,510),('Continuous Sync',1556,511)])
        result=json_result(record('data_flow_fixture',system_id='integration_service',record_type='DATA_FLOW'),'corroboration',6)
        o=validated_ocr_observations((doc,),pipeline([result]).index)[0]
        self.assertEqual(temporal_rejection(o,moment(5)),'embedded_clock_after_cutoff')
        changed=replace(doc,regions=tuple(freeze({**dict(region),'text':region['text'].replace('data_flow_fixture','data_flow_fixlure')}) for region in doc.regions))
        self.assertFalse(validated_ocr_observations((changed,),pipeline([result]).index))

    def test_ocr_marketing_owner_is_actual_visible_email(self):
        doc=self.visual([('Audience Operations',250,20),('marketing_fixture different@example.test +1 555 0101',250,140),
                         ('Last refreshed',1250,235),('02 Jan 2025 12:00 UTC',1250,255)])
        result=json_result(record('marketing_fixture',system_id='marketing_platform',record_type='MARKETING_PROFILE',email='new@example.test'))
        o=validated_ocr_observations((doc,),pipeline([result]).index)[0]
        self.assertEqual(o.attributes['email'],'different@example.test')
        self.assertNotEqual(o.attributes['email'],result.observations[0].attributes['email'])

    def test_old_and_current_hashes_link_but_competing_owner_does_not(self):
        result=extract('.log','\n'.join([
            '2025-01-02T00:00:00Z service=account_service event=profile_lookup_completed lookup_key=OldHash resource_id=old-profile rows=0 http_status=404',
            '2025-01-02T00:00:00Z service=account_service event=profile_lookup_completed lookup_key=NewHash resource_id=current-profile rows=0 http_status=404',
            '2025-01-02T00:00:00Z service=account_service event=profile_lookup_completed lookup_key=OtherHash resource_id=decoy rows=1 http_status=200']))
        def identity(other_hash):
            return IdentityIndex([snapshot(day=3,email_hash='NewHash'),snapshot('other','other@example.test',phone='OtherPhone',email_hash=other_hash)],
                                 [change(field='email_hash',old='OldHash',new='NewHash')])
        for other_hash,expected in [('OtherHash',{'old-profile','current-profile'}),('OldHash',{'current-profile'})]:
            p=pipeline([result],identity(other_hash))
            linked=p.index.find_subject_evidence(p.index.identity_index.resolve_request('new@example.test',moment(5)),moment(5))
            self.assertEqual({m.observation.resource_id for m in linked.matches},expected)
            if other_hash=='OldHash':
                self.assertIsNone(p.audit(case()).result)

    def test_policy_condition_certificate_cannot_cite_invented_source(self):
        from ghost_audit.output import validate_case
        result=json_result(record('retained',system_id='security_service',record_type='SECURITY_AUDIT_LOG',
                                  user_id='subject-a',retention_until='2030-01-01T00:00:00Z'))
        p=pipeline([result]);request=replace(case(),request_text='Remove my personal information.');out=p.audit(request)
        d=out.decisions[0]
        changed=replace(d,condition_proofs=(replace(d.condition_proofs[0],evidence_id='not-a-source'),))
        bindings=tuple(replace(b,decisions=tuple(changed if value==d else value for value in b.decisions)) for b in out.bindings)
        with self.assertRaisesRegex(ValueError,'invalid_policy_condition_source'):
            validate_case(replace(out,decisions=(changed,),bindings=bindings),request,p.index)

    def test_no_direct_identifier_placeholder_is_not_a_stable_user_id(self):
        result=extract('.txt','- 2025-01-02T00:00:00Z | analytics_platform | aggregate | ANALYTICS_PROFILE | ANONYMIZED | no direct identifier')
        facts,gaps=normalize_facts(result.observations[0])
        self.assertFalse(any(f.dimension.startswith('stable_reference:') and f.value=='PRESENT' for f in facts))
        self.assertIn('non_identifier_reference_placeholder',gaps)
