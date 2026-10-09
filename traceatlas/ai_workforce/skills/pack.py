"""Bind the repository's offline skill pack to the existing Employee runtime."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

from traceatlas.ai_workforce.employee import Employee, JobDescription, ModelPolicy
from traceatlas.ai_workforce.result import ResultStatus


def _runner():
    name='_traceatlas_skill_pack_runner'
    if name not in sys.modules:
        path=Path(__file__).resolve().parents[3]/'skill/traceatlas-intelligence/scripts/run_skill.py'
        spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        sys.modules[name]=module
    return sys.modules[name]


def list_pack_skills() -> list[str]:
    return list(_runner().MODULES)


def build_pack_employee(domain: str) -> Employee:
    runner=_runner()
    domain=runner.ALIASES.get(domain.lower(),domain.lower())
    if domain not in runner.MODULES:
        raise ValueError('No executable offline binding for '+domain)
    employee=Employee(
        name=domain+' Offline Analyst', role=domain, department='offline_intelligence',
        job=JobDescription(role=domain,mission='Analyze supplied authorized local records',
                           accepted_tasks=['offline_'+domain],required_skills=['offline_analysis'],
                           allowed_sources=['local_record'],
                           prohibited_actions=['live_collection','canonical_fact_promotion']),
        skills=['offline_analysis'],model_policy=ModelPolicy(provider='deterministic',allow_cloud=False))

    def handler(inputs):
        result=runner.run(domain,inputs)
        status=str(result['status']).upper()
        if status.startswith(('BLOCKED','POLICY_BLOCKED')):
            mapped=ResultStatus.BLOCKED
        elif status.startswith(('FAILED','ERROR')):
            mapped=ResultStatus.FAILED
        else:
            mapped=ResultStatus.PARTIAL
        # Native heuristic "facts" are retained as analysis, never promoted here.
        return {'status':mapped, 'observations':[{'statement':'Offline analysis output',
                 'analysis_result':result, 'statement_type':'analysis', 'evidence_ids':[]}],
                'limitations':result.get('limitations',[])+([result['error']] if 'error' in result else []),
                'unknowns':['Canonical evidence ingestion and fact-gate review are required.']}
    employee.register_handler('offline_analysis',handler)
    return employee
