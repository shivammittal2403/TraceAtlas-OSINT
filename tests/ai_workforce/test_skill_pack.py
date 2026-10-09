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
