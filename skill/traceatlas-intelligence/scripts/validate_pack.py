#!/usr/bin/env python3
"""Validate skill metadata, original integrity, graph parity and derived modules."""
from pathlib import Path
import ast
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
def validate():
    skill=(ROOT/'SKILL.md').read_text()
    assert skill.startswith('---\nname: traceatlas-intelligence\n')
    assert len(skill.splitlines())<500
    for link in re.findall(r'\]\(([^)]+)\)',skill):
        assert (ROOT/link).is_file(), 'Broken skill reference: '+link
    manifest=json.loads((ROOT/'references/source-manifest.json').read_text())
    assert manifest['source_count']==29==len(manifest['sources'])
    for source in manifest['sources']:
        data=(ROOT/source['path']).read_bytes()
        assert len(data)==source['bytes']
        assert hashlib.sha256(data).hexdigest()==source['sha256'],source['path']
    catalog=json.loads((ROOT/'references/intelligence-catalog.json').read_text())
    assert len(catalog['entries'])==catalog['count']==140
    assert [x['number'] for x in catalog['entries']]==list(range(1,141))
    assert len({x['id'] for x in catalog['entries']})==140
    for item in catalog['entries']:
        for ref in item['references']:
            assert (ROOT/ref).is_file(),ref
        if item['runtime_binding']:
            assert (ROOT/item['runtime_binding']).is_file()
    graph=json.loads((ROOT/'references/graph-memory.json').read_text())
    ids={node['id'] for node in graph['nodes']}
    assert len(ids)==len(graph['nodes'])==434
    assert len(graph['edges'])==671
    assert all(e['source'] in ids and e['target'] in ids for e in graph['edges'])
    a=(ROOT/'references/memory-graph.graphml').read_bytes()
    assert a==(ROOT/'references/memory-graph-copy.graphml').read_bytes()
    xml=ET.fromstring(a);ns={'g':'http://graphml.graphdrawing.org/xmlns'}
    assert {n.attrib['id'] for n in xml.findall('.//g:node',ns)}==ids
    assert len(xml.findall('.//g:edge',ns))==671
    ledger=json.loads((ROOT/'references/repair-ledger.json').read_text())
    assert len(ledger['repaired_modules'])==20
    for module in ledger['repaired_modules']:
        path=ROOT/module['path'];data=path.read_bytes()
        assert hashlib.sha256(data).hexdigest()==module['sha256'],str(path)
        compile(data,str(path),'exec')
    reuploads=json.loads((ROOT/'references/reupload-audit.json').read_text())
    assert reuploads['submitted_files']==20==len(reuploads['files'])
    assert reuploads['identical_reuploads']==sum(row['identical_to_archived_source'] for row in reuploads['files'])==17
    assert reuploads['distinct_variants']==3
    assert len({row['domain'] for row in reuploads['files']})==20
    for row in reuploads['files']:
        data=(ROOT/row['archived_path']).read_bytes()
        assert len(data)==row['bytes']
        assert hashlib.sha256(data).hexdigest()==row['sha256'],row['uploaded_name']
        assert (ROOT/row['corrected_path']).is_file()
    json.loads((ROOT/'references/chat-export.json').read_text())
    return {'status':'PASS','originals':29,'rechecked_uploads':20,'distinct_reupload_variants':3,
            'catalog_entries':140,'corrected_modules':20,
            'graph_nodes':434,'graph_edges':671}

if __name__=='__main__':
    try:print(json.dumps(validate(),indent=2))
    except (AssertionError,OSError,ValueError,SyntaxError) as exc:
        print('FAIL: '+str(exc),file=sys.stderr);raise SystemExit(1)
