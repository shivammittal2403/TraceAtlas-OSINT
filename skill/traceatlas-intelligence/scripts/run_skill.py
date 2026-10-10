#!/usr/bin/env python3
"""Execute the supplied local analysis modules through one explicit contract.

This runner performs no live collection, model calls or canonical fact promotion.
The imported modules retain their native results and limitations.
"""
from __future__ import annotations

import argparse
import dataclasses
from datetime import datetime
from enum import Enum
import importlib.util
import inspect
import json
import math
from pathlib import Path
import sys
import types
from typing import Any, get_args, get_origin, get_type_hints, Union

MODULES = (
    'academicint', 'acoustint', 'adsbint', 'aiint', 'aisint', 'anomalyint',
    'assetint', 'audint', 'automotiveint', 'aviation_cyber_int', 'aviint',
    'behaviouralint', 'brandint', 'breachint', 'cloudint', 'codeint', 'comint',
    'containerint', 'contradictionint', 'companyint',
)
ALIASES = {'corpint':'companyint', 'airint':'aviint', 'behavint':'behaviouralint'}
ROOT = Path(__file__).resolve().parent
MAX_INPUT_BYTES = 16 * 1024 * 1024


def load_module(domain):
    domain = ALIASES.get(domain.lower(), domain.lower())
    if domain not in MODULES:
        raise ValueError('Unknown or unimplemented skill: ' + domain)
    name = '_traceatlas_pack_' + domain
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, ROOT / (domain + '.py'))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(name, None)
            raise
    return sys.modules[name]


def jsonable(value):
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if dataclasses.is_dataclass(value):
        return {f.name:jsonable(getattr(value,f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {str(k):jsonable(v) for k,v in value.items()}
    if isinstance(value, (list,tuple,set)):
        return [jsonable(v) for v in value]
    if value is None or isinstance(value,(str,int,float,bool)):
        return value
    raise TypeError('Unsupported result type: ' + type(value).__name__)


def decode_value(value, hint):
    """Validate JSON values before constructing native typed records."""
    origin = get_origin(hint)
    if origin in (Union,types.UnionType):
        for alternative in get_args(hint):
            try:
                return decode_value(value,alternative)
            except (ValueError,TypeError):
                pass
        raise ValueError('Value does not match any permitted field type')
    if hint in (Any,object):
        return value
    if hint is type(None):
        if value is not None:
            raise ValueError('Expected null')
        return None
    if isinstance(hint,type) and issubclass(hint,Enum):
        return hint(value)
    if dataclasses.is_dataclass(hint):
        return decode_record(hint,value)
    if origin is list:
        if not isinstance(value,list):
            raise ValueError('Expected a JSON array')
        return [decode_value(item,get_args(hint)[0]) for item in value]
    if origin is dict:
        if not isinstance(value,dict):
            raise ValueError('Expected a JSON object')
        key_type,value_type = get_args(hint)
        return {decode_value(key,key_type):decode_value(item,value_type) for key,item in value.items()}
    if hint is str and not isinstance(value,str):
        raise ValueError('Expected a JSON string')
    if hint is bool and type(value) is not bool:
        raise ValueError('Expected a JSON boolean')
    if hint is int and type(value) is not int:
        raise ValueError('Expected a JSON integer')
    if hint is float:
        try:
            finite = type(value) in (int,float) and math.isfinite(value)
        except OverflowError:
            finite = False
        if not finite:
            raise ValueError('Expected a finite JSON number')
    return value


def decode_record(cls, data):
    if not isinstance(data, dict):
        raise ValueError(cls.__name__ + ' record must be a JSON object')
    fields = {f.name for f in dataclasses.fields(cls)}
    unknown = set(data) - fields
    if unknown:
        raise ValueError(cls.__name__ + ' unknown fields: ' + ', '.join(sorted(unknown)))
    hints = get_type_hints(cls)
    values={key:decode_value(value,hints.get(key,Any)) for key,value in data.items()}
    if 'id' in values and isinstance(values['id'],str) and not values['id'].strip():
        raise ValueError(cls.__name__ + ' id must not be empty')
    return cls(**values)


def validate_manifest(manifest):
    if not isinstance(manifest,dict):
        raise ValueError('Manifest must be a JSON object')
    for field in ('case_id','task_id','objective'):
        if not isinstance(manifest.get(field),str) or not manifest[field].strip():
            raise ValueError('Manifest requires ' + field)
    auth = manifest.get('authorization')
    if not isinstance(auth,dict) or auth.get('approved') is not True:
        raise ValueError('Explicit authorization.approved=true is required')
    if auth.get('case_id') != manifest['case_id']:
        raise ValueError('Authorization is not bound to this case')
    if not isinstance(auth.get('basis'),str) or not auth['basis'].strip():
        raise ValueError('Authorization basis is required')
    if manifest.get('model_mode','LOCAL_ONLY') != 'LOCAL_ONLY':
        raise ValueError('This runner supports LOCAL_ONLY analysis')
    if manifest.get('sample'):
        raise ValueError('Use native --sample explicitly; the shared runner does not substitute demo data')


def input_file(manifest):
    supplied = manifest.get('input_file')
    if not isinstance(supplied,str) or not supplied:
        raise ValueError('This file-analysis skill requires input_file')
    root = manifest['authorization'].get('allowed_root')
    if not isinstance(root,str) or not root:
        raise ValueError('File analysis requires authorization.allowed_root')
    path = Path(supplied).expanduser().resolve(strict=True)
    allowed = Path(root).expanduser().resolve(strict=True)
    if not path.is_relative_to(allowed) or not path.is_file():
        raise ValueError('Input file is outside the allowed root or is not regular')
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError('Input file exceeds 16 MiB')
    return str(path)


def _native(domain, module, manifest):
    functions = {
        'academicint':'analyze_academicint_manifest', 'acoustint':'analyze',
        'adsbint':'analyze', 'anomalyint':'analyze_anomaly_manifest',
        'assetint':'analyze_assetint_manifest', 'automotiveint':'analyze_automotiveint_manifest',
        'behaviouralint':'analyze_behavint_manifest', 'brandint':'analyze_brandint_manifest',
        'contradictionint':'analyze',
    }
    if domain in functions:
        return getattr(module,functions[domain])(manifest)
    if domain in ('aiint','containerint'):
        cls = module.AIIntEmployee if domain=='aiint' else module.ContainerIntEmployee
        scope = manifest.get('scope')
        if not isinstance(scope,dict):
            raise ValueError('This skill requires scope as an object')
        return cls(model_mode='LOCAL_ONLY').process_case(
            manifest['case_id'], manifest['task_id'], manifest['objective'], scope,
            manifest.get('evidence_input',{}), manifest.get('known_facts'))
    if domain=='aisint':
        data = dict(manifest)
        data['authorization'] = manifest['authorization']['basis']
        return module.AISIntelligenceEmployee().run_case(data)
    if domain=='aviation_cyber_int':
        request = module.Request(
            case_id=manifest['case_id'], objective=manifest['objective'],
            scope=manifest.get('scope',{}), authorization=manifest['authorization'],
            evidence=[decode_record(module.Evidence,e) for e in manifest.get('evidence',[])],
            time_range=manifest.get('time_range',{}))
        return module.AviationCyberInt().analyze(request)
    if domain in ('cloudint','codeint'):
        supplied_case = manifest.get('case',{})
        collections = manifest.get('records',{})
        if not isinstance(supplied_case,dict):
            raise ValueError('case must be a JSON object')
        if not isinstance(collections,dict):
            raise ValueError('records must be a JSON object')
        case_data = dict(supplied_case)
        case_data.update(case_id=manifest['case_id'], task_id=manifest['task_id'],
                         objective=manifest['objective'], authorization=manifest['authorization']['basis'],sample=False)
        case = decode_record(module.Case,case_data)
        violations = module.policy_guard(case.objective)
        if violations:
            return module.blocked_policy_result(case,violations)
        analyst = module.CloudInt(case) if domain=='cloudint' else module.CodeInt(case)
        ingested_count = 0
        for collection,records in collections.items():
            if not isinstance(collection,str):
                raise ValueError('Record collection name must be a string')
            method = getattr(analyst,'add_'+collection,None)
            if not callable(method):
                raise ValueError('Unsupported record collection: ' + collection)
            parameter = next(iter(inspect.signature(method).parameters))
            hint = get_type_hints(method)[parameter]
            if not isinstance(records,list):
                raise ValueError('Record collection must be an array')
            for record in records:
                method(decode_value(record,hint))
                ingested_count += 1
        analyst.prepare()
        # Preserve the actual typed state; no synthetic sample replacement or AI-review claim.
        return {'status':'ANALYZED_LOCAL' if ingested_count else 'INSUFFICIENT_DATA',
                'ingested_record_count':ingested_count,
                **{key:jsonable(value) for key,value in vars(analyst).items() if not key.startswith('_')}}
    files = {'audint':'analyze_audio_file','aviint':'analyze_av_file',
             'breachint':'analyze_breach_file','comint':'analyze_communication_file',
             'companyint':'analyze_corporate_file'}
    path = input_file(manifest)
    if hasattr(module,'policy_screen'):
        policy = module.policy_screen(manifest)
        if policy.get('status')=='POLICY_BLOCKED':
            return policy
    if domain=='audint':
        return module.analyze_audio_file(path)
    native = getattr(module,files[domain])(path,case_id=manifest['case_id'],task_id=manifest['task_id'])
    if domain=='companyint':
        file_evidence, parsed = native
        if file_evidence.get('error') or str(file_evidence.get('status','')).startswith('FAILED'):
            return native
        return {'status':file_evidence['status'], 'file_evidence':file_evidence,
                'parsed':module.finalize_parsed(parsed,payload=manifest,files=[file_evidence])}
    return native


def run(domain, manifest):
    try:
        if not isinstance(domain,str):
            raise ValueError('Skill name must be a string')
        domain = ALIASES.get(domain.lower(),domain.lower())
        validate_manifest(manifest)
        module = load_module(domain)
        native = _native(domain,module,manifest)
        result = jsonable(native)
        # Apply the existing nested secret redaction before returning local artifacts.
        repo_root=ROOT.parents[2]
        if str(repo_root) not in sys.path:
            sys.path.insert(0,str(repo_root))
        from allint52._support import redact_text
        def clean_strings(value):
            if isinstance(value,str):
                return redact_text(value)
            if isinstance(value,list):
                return [clean_strings(item) for item in value]
            if isinstance(value,dict):
                return {key:clean_strings(item) for key,item in value.items()}
            return value
        result=json.loads(redact_text(json.dumps(clean_strings(result),ensure_ascii=False,allow_nan=False)))
        # Preserve native failure states rather than treating every return as success.
        state = result.get('status','ANALYZED_LOCAL') if isinstance(result,dict) else 'ANALYZED_LOCAL'
        if isinstance(result,list) and result and isinstance(result[0],dict):
            state=result[0].get('status',state)
            if result[0].get('error'):
                state='FAILED_ANALYSIS'
        if domain in ('cloudint','codeint') and not manifest.get('records'):
            state='INSUFFICIENT_DATA'
        return {'status':state, 'domain':domain, 'case_id':manifest['case_id'],
                'source_mode':'PROVIDED_LOCAL_RECORDS', 'native_result':result,
                'canonical_verification':'NOT_PROMOTED_TO_CANONICAL_FACTS',
                'limitations':['Offline prototype analysis; no live source or independent AI review was performed.']}
    except (ValueError,TypeError,KeyError,OSError) as exc:
        return {'status':'BLOCKED_INVALID_INPUT','domain':domain,'error':str(exc),
                'canonical_verification':'NOT_PROMOTED_TO_CANONICAL_FACTS'}
    except Exception as exc:
        return {'status':'FAILED_INTERNAL','domain':domain,'error':type(exc).__name__,
                'canonical_verification':'NOT_PROMOTED_TO_CANONICAL_FACTS'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('domain',nargs='?')
    parser.add_argument('--manifest',type=Path)
    parser.add_argument('--list',action='store_true')
    args = parser.parse_args()
    if args.list:
        print(json.dumps({'modules':MODULES,'aliases':ALIASES},indent=2));return 0
    if not args.domain or not args.manifest:
        parser.error('domain and --manifest are required')
    try:
        if args.manifest.stat().st_size>MAX_INPUT_BYTES:
            raise ValueError('Manifest exceeds 16 MiB')
        result=run(args.domain,json.loads(args.manifest.read_text(encoding='utf-8')))
    except (OSError,ValueError) as exc:
        result={'status':'BLOCKED_INVALID_INPUT','error':str(exc)}
    print(json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False))
    return 2 if str(result['status']).startswith(('BLOCKED','FAILED','POLICY_BLOCKED')) else 0


if __name__=='__main__':
    raise SystemExit(main())
