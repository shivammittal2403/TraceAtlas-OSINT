"""Offline skill regressions covering authority, real inputs and file boundaries."""
import dataclasses
import json
from pathlib import Path
import pytest
from traceatlas.ai_workforce.employee import ModelPolicy
from traceatlas.ai_workforce.skills.pack import _runner, build_pack_employee, list_pack_skills
from traceatlas.ai_workforce.task import Authorization, Scope, Task
from traceatlas.ai_workforce.result import ResultStatus

MODULES=list_pack_skills()

def manifest(**extra):
    data={'case_id':'fixture-case','task_id':'fixture-task',
          'objective':'Review authorized defensive historical records',
          'authorization':{'approved':True,'case_id':'fixture-case','basis':'synthetic fixture'},'scope':{}}
    data.update(extra)
    return data

@pytest.mark.parametrize('domain',MODULES)
def test_missing_authority_blocks_every_native_module(domain):
    result=_runner().run(domain,{'case_id':'fixture-case'})
    assert result['status']=='BLOCKED_INVALID_INPUT'
    assert 'native_result' not in result

@pytest.mark.parametrize('domain',MODULES)
def test_all_modules_import_without_gui_or_demo(domain):
    assert _runner().load_module(domain).__name__

def test_case_mismatch_and_cloud_mode_are_denied():
    case=manifest();case['authorization']['case_id']='another-case'
    assert _runner().run('aisint',case)['status']=='BLOCKED_INVALID_INPUT'
    assert _runner().run('aiint',manifest(model_mode='CLOUD'))['status']=='BLOCKED_INVALID_INPUT'

@pytest.mark.parametrize('provider',['openai','anthropic','deterministic','ollama'])
def test_local_only_checks_provider(provider):
    for allow_cloud in (True,False):
        assert ModelPolicy(provider=provider,allow_cloud=allow_cloud).usable_in_local_only_mode()==(provider in {'deterministic','ollama'})

def test_employee_preserves_native_output_as_analysis():
    task=Task(question='Review fixture',case_id='fixture-case',required_skills=['offline_analysis'],
              evidence_requirements=['local_record'],scope=Scope(entities=['fixture']),
              authorization=Authorization(case_id='fixture-case'),inputs=manifest())
    result=build_pack_employee('academicint').run(task)
    assert result.status==ResultStatus.PARTIAL
    assert not result.candidate_facts
    assert result.observations[0]['analysis_result']['canonical_verification']=='NOT_PROMOTED_TO_CANONICAL_FACTS'

def test_company_file_ingestion_scope_and_redaction(tmp_path):
    source=tmp_path/'registry.json'
    source.write_text(json.dumps({'company_name':'Fixture Ltd','company_id':'FIX-001','password':'must-not-leak'}))
    case=manifest(input_file=str(source));case['authorization']['allowed_root']=str(tmp_path)
    result=_runner().run('corpint',case)
    assert not result['status'].startswith(('FAILED','BLOCKED'))
    assert 'Fixture' in json.dumps(result)
    assert 'must-not-leak' not in json.dumps(result)
    outside=tmp_path/'sub';outside.mkdir();case['authorization']['allowed_root']=str(outside)
    assert _runner().run('companyint',case)['status']=='BLOCKED_INVALID_INPUT'

def test_missing_cloud_code_inputs_remain_insufficient():
    for domain in ('cloudint','codeint'):
        assert _runner().run(domain,manifest())['status']=='INSUFFICIENT_DATA'
        assert _runner().run(domain,manifest(sample=True))['status']=='BLOCKED_INVALID_INPUT'

def test_company_roles_source_identity_zero_ownership_and_final_analysis(tmp_path):
    source=tmp_path/'registry.json'
    source.write_text(json.dumps({
        'name':'Fixture Ltd', 'company_id':'source-id-001',
        'directors':[{'name':'Alex Example'}],
        'shareholders':[{'name':'Jamie Example','percentage':0,'ownership_share':75}],
    }))
    case=manifest(input_file=str(source));case['authorization']['allowed_root']=str(tmp_path)
    result=_runner().run('companyint',case)
    assert result['status']=='SUCCEEDED',result
    parsed=result['native_result']['parsed']
    assert [company['legal_name'] for company in parsed['companies']]==['Fixture Ltd']
    assert parsed['companies'][0]['source_company_id']=='source-id-001'
    assert not parsed['companies'][0]['registration_number']
    assert [person['name'] for person in parsed['persons']]==['Alex Example']
    assert parsed['relationships'][0]['percentage']==0
    assert any('Registration numbers' in gap['missing_evidence'] for gap in parsed['knowledge_gaps'])
    assert parsed['specialist_handoffs'][0]['specialist']=='OWNERSHIPINT'
    assert result['canonical_verification']=='NOT_PROMOTED_TO_CANONICAL_FACTS'

def test_real_cloud_records_are_ingested():
    module=_runner().load_module('cloudint')
    fields={f.name for f in dataclasses.fields(module.Resource)}
    hints=__import__('typing').get_type_hints(module.Resource)
    kind=hints['resource_type']
    values={'id':'res-fixture','resource_type':list(kind)[0].value if hasattr(kind,'__members__') else 'storage_bucket'}
    values.update(tenant_id='fixture-tenant',account_id='fixture-account')
    if 'provider' in fields:
        hint=hints['provider']
        values['provider']=list(hint)[0].value if hasattr(hint,'__members__') else 'fixture'
    result=_runner().run('cloudint',manifest(records={'resource':[values]}))
    assert result['status']=='ANALYZED_LOCAL',result
    assert 'res-fixture' in json.dumps(result['native_result'])

def test_numeric_contradiction_units_and_ranges():
    module=_runner().load_module('contradictionint')
    assert module.parse_object('1.5 million usd')['value']==1_500_000
    bounds=module.parse_object('10.5 to 12.5')
    assert (bounds['low'],bounds['high'])==(10.5,12.5)

@pytest.mark.parametrize('domain,collection',[('cloudint','resource'),('codeint','repository')])
def test_empty_record_arrays_have_no_analysis_or_sample_recommendations(domain,collection):
    result=_runner().run(domain,manifest(records={collection:[]}))
    assert result['status']=='INSUFFICIENT_DATA',result
    native=result['native_result']
    assert native['ingested_record_count']==0
    assert native['recommendations']==[]
    assert native['handoffs']==[]
    assert len(native['actions'])==1
    assert native['actions'][0]['id']=='ACT-CONFIGURE-EVIDENCE'
    assert 'STG-777' not in json.dumps(native)
    assert native.get('risk_dimensions',{}).get('EVIDENCE_CONFIDENCE','UNKNOWN_NO_EVIDENCE')=='UNKNOWN_NO_EVIDENCE'

@pytest.mark.parametrize('domain',['cloudint','codeint'])
@pytest.mark.parametrize('records',[None,[],17,'invalid'])
def test_wrong_record_map_shape_is_invalid_input(domain,records):
    result=_runner().run(domain,manifest(records=records))
    assert result['status']=='BLOCKED_INVALID_INPUT',result

@pytest.mark.parametrize('extra',[
    {'case':[]},
    {'records':{'source':[{'id':'s1','title':'Fixture','url':'','source_type':'OTHER','reliability':'invalid'}]}},
    {'records':{'source':[{'id':'s1','title':'Fixture','url':'','source_type':'OTHER','reliability':True}]}},
    {'records':{'source':[{'id':'s1','title':'Fixture','url':'','source_type':'OTHER','reliability':float('nan')}]}},
    {'records':{'source':[{'id':'s1','title':'Fixture','url':'','source_type':'OTHER','reliability':10**400}]}},
    {'records':{'resource':[{'id':'r1','provider':17,'tenant_id':'fixture','account_id':'fixture'}]}},
    {'records':{'resource':[{'id':'r1','provider':'fixture','tenant_id':'fixture','account_id':'fixture','tags':[]}]}},
    {'records':{'resource':[{'id':'','provider':'fixture','tenant_id':'fixture','account_id':'fixture'}]}},
])
def test_cloud_scalar_and_nested_types_are_validated(extra):
    assert _runner().run('cloudint',manifest(**extra))['status']=='BLOCKED_INVALID_INPUT'

@pytest.mark.parametrize('extra',[
    {'records':{'repository':[{'id':'repo1','name':17,'remote_reference':'local'}]}},
    {'records':{'file':[{'id':'file1','repository_id':'repo1','commit_id':'commit1','path':None}]}},
    {'records':{'documentation_claim':['invalid']}},
    {'records':{'file':[{'id':'file1','repository_id':'repo1','commit_id':'commit1','path':'fixture.py','size':True}]}},
])
def test_code_scalar_and_dictionary_types_are_validated(extra):
    assert _runner().run('codeint',manifest(**extra))['status']=='BLOCKED_INVALID_INPUT'

@pytest.mark.parametrize('resource_id',['resource-secret','resource-password','resource-api_key'])
def test_sensitive_suffix_in_resource_id_does_not_corrupt_json(resource_id):
    result=_runner().run('cloudint',manifest(records={'resource':[{
        'id':resource_id,'provider':'fixture','tenant_id':'fixture','account_id':'fixture',
        'tags':{'password':'fixture-sensitive-value','note':'token=fixture-token-value'},
    }]}))
    assert result['status']=='ANALYZED_LOCAL',result
    assert resource_id in result['native_result']['resources']
    serialized=json.dumps(result)
    assert 'fixture-sensitive-value' not in serialized
    assert 'fixture-token-value' not in serialized

@pytest.mark.parametrize('mismatch',['authorization','input'])
def test_employee_blocks_case_mismatch_before_analysis(mismatch):
    case=manifest()
    authorization=Authorization(case_id='fixture-case')
    if mismatch=='authorization':authorization.case_id='another-case'
    else:case['case_id']='another-case';case['authorization']['case_id']='another-case'
    task=Task(question='Review fixture',case_id='fixture-case',required_skills=['offline_analysis'],
              evidence_requirements=['local_record'],authorization=authorization,inputs=case)
    result=build_pack_employee('academicint').run(task)
    assert result.status==ResultStatus.BLOCKED
    assert not result.observations

@pytest.mark.parametrize('domain',['cloudint','codeint'])
def test_native_empty_exports_preserve_missing_data(domain):
    module=_runner().load_module(domain)
    case=module.Case(case_id='fixture-case',task_id='fixture-task',objective='Review authorized local fixture',authorization='Synthetic fixture')
    result=_runner().jsonable(module.run_unconfigured_pipeline(case))
    assert result['status']=='BLOCKED_CONFIGURATION'
    assert result['timeline_updates']==[]
    assert 'STG-777' not in json.dumps(result)
    assert 'C-HEAD' not in json.dumps(result)
    if domain=='cloudint':
        assert result['config_drift']==[]
        assert result['data_residency']=={}
    else:
        for field in ('databases','ci_cd_pipelines','artifacts','containers','security_controls',
                      'authentication_context','authorization_context','database_context','input_validation_context'):
            assert result[field]==[],field

def test_cloud_recommendations_reference_supplied_findings_and_evidence():
    result=_runner().run('cloudint',manifest(records={
        'source':[{'id':'fixture-source','title':'Fixture config','url':'','source_type':'CLOUD_NATIVE_CONFIG'}],
        'evidence':[{'id':'fixture-evidence','source_id':'fixture-source','artifact_type':'configuration','excerpt':'Synthetic local configuration record'}],
        'resource':[{'id':'fixture-bucket','provider':'fixture','tenant_id':'fixture','account_id':'fixture'}],
        'finding':[{'id':'fixture-finding','finding_type':'PUBLIC_ACCESS_CONFIGURATION_CANDIDATE',
                    'subject_id':'fixture-bucket','statement':'Review supplied public configuration candidate',
                    'risk_dimension':'DATA_EXPOSURE','source_ids':['fixture-source'],'evidence_ids':['fixture-evidence']}],
    }))
    assert result['status']=='ANALYZED_LOCAL',result
    recommendations=result['native_result']['recommendations']
    assert len(recommendations)==1
    assert recommendations[0]['target']=='fixture-bucket'
    assert recommendations[0]['finding_ids']==['fixture-finding']
    assert recommendations[0]['evidence_ids']==['fixture-evidence']

def test_recorded_cloud_history_uses_actual_snapshots():
    module=_runner().load_module('cloudint')
    analyst=module.CloudInt(module.Case(case_id='fixture-case',task_id='fixture-task',objective='Review fixture'))
    analyst.add_resource(module.Resource(id='fixture-bucket',provider='fixture',tenant_id='fixture',account_id='fixture',region='fixture-region'))
    for identifier,date,enabled in [('snapshot1','2026-01-01T00:00:00Z',False),('snapshot2','2026-02-01T00:00:00Z',True)]:
        analyst.add_config_snapshot(module.ConfigSnapshot(id=identifier,resource_id='fixture-bucket',config_type='fixture',valid_from=date,attributes={'enabled':enabled}))
    analyst.prepare()
    result=_runner().jsonable(module.build_result(analyst,module.Status.PARTIAL))
    assert result['config_drift'][0]['resource_id']=='fixture-bucket'
    assert result['config_drift'][0]['snapshot_ids']==['snapshot1','snapshot2']
    assert result['data_residency']['fixture-bucket']['observed_region']=='fixture-region'
    assert [event['snapshot_id'] for event in result['timeline_updates']]==['snapshot1','snapshot2']
    assert result['dual_ai_review']['independent_review_performed'] is False
    assert 'STG-777' not in result['analyst_summary']

@pytest.mark.parametrize('domain,collection,record',[
    ('cloudint','resource',{'id':'fixture-resource','provider':'fixture','tenant_id':'fixture','account_id':'fixture'}),
    ('codeint','repository',{'id':'fixture-repo','name':'Fixture','remote_reference':'local'}),
])
def test_metadata_only_handoffs_and_actions_have_current_case_basis(domain,collection,record):
    result=_runner().run(domain,manifest(records={collection:[record]}))
    assert result['status']=='ANALYZED_LOCAL',result
    native=result['native_result']
    basis={gap['id'] for gap in native['gaps']} | set(native['findings'])
    assert all(handoff['basis_id'] in basis for handoff in native['handoffs'])
    assert all(handoff['specialist'] not in {'CREDINT','VULNINT','INCIDENTINT','LEGALINT'} for handoff in native['handoffs'])
    assert len(native['actions'])==len(native['gaps'])

@pytest.mark.parametrize('resource_types,logged_ids,missing_ids',[
    ([],[],[]),
    (['UNKNOWN'],[],[]),
    (['OBJECT_STORAGE'],[],['resource-0']),
    (['OBJECT_STORAGE'],['resource-0'],[]),
    (['OBJECT_STORAGE','OBJECT_STORAGE'],['resource-0'],['resource-1']),
])
def test_cloud_storage_log_gaps_require_matching_supplied_resources(resource_types,logged_ids,missing_ids):
    records={
        'resource':[{'id':f'resource-{index}','provider':'fixture','tenant_id':'fixture',
                     'account_id':'fixture','resource_type':kind} for index,kind in enumerate(resource_types)],
        'audit_event':[{'id':f'event-{identifier}','provider':'fixture','account_id':'fixture',
                        'event_name':'read','resource_id':identifier,'data_plane':True} for identifier in logged_ids],
    }
    result=_runner().run('cloudint',manifest(records=records))
    native=result['native_result']
    gaps=[gap for gap in native['gaps'] if gap['id'].startswith('GAP-DPLOG-')]
    assert [gap['about_resource_ids'][0] for gap in gaps]==missing_ids
    if not missing_ids:
        assert all('storage access logs' not in action['description'] for action in native['actions'])
        assert all('storage access logs' not in handoff['reason'] for handoff in native['handoffs'])
