"""Offline package integrity and privacy checks; no installation or game launch."""
from pathlib import Path
import getpass, hashlib, json, re, zlib

def main():
    root=Path(__file__).resolve().parents[2]
    manifest=json.loads((root/'dev/manifests/export.json').read_text(encoding='utf-8'))
    failures=[]
    expected={r['path'] for r in manifest['files']}
    actual={p.relative_to(root).as_posix() for folder in ('mods','profiles') for p in (root/folder).rglob('*') if p.is_file()}
    if actual!=expected:
        failures.append({'type':'unexpected or missing package files','paths':sorted(actual^expected)})
    for row in manifest['files']:
        p=root/row['path']
        if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=row['sha256']:
            failures.append({'type':'hash mismatch','path':row['path']})
    patterns={
        'private user or host':rb'(?i)DESKTOP-[A-Z0-9]+|[A-Z]:[\\/]+Users[\\/]+',
        'original installation path':rb'(?i)[A-Z]:[\\/]+Modlists[\\/]+F4_LITR',
        'credential signature':rb'(?:ghp_|github_pat_|sk-proj-)[A-Za-z0-9_]{12,}',
        'nonempty credential assignment':rb'(?im)^\s*(?:api_?key|access_?token|password|nexus_?token)\s*[=:]\s*[^\s;#\r\n]+'
    }
    username=getpass.getuser().encode('utf-8')
    if len(username)>=4:
        patterns['current user identifier']=rb'(?i)'+re.escape(username)
    scanned=0
    for p in root.rglob('*'):
        if not p.is_file() or p.name.endswith('.local.md') or any(x in {'.git','__pycache__','audit-local'} for x in p.relative_to(root).parts):continue
        rel=p.relative_to(root).as_posix()
        if '.bak' in p.name.lower() or p.suffix.lower() in {'.pdb','.fos','.f4se','.log','.dmp','.tmp'}:
            failures.append({'type':'excluded extension','path':rel})
        if p.stat().st_size>100*1024*1024:
            failures.append({'type':'GitHub file size limit','path':rel})
        b=p.read_bytes()
        if p.suffix.lower()=='.swf' and b[:3]==b'CWS':
            b=b[:8]+zlib.decompress(b[8:])
        elif p.suffix.lower()=='.swf' and b[:3]==b'ZWS':
            failures.append({'type':'unsupported compressed SWF needs review','path':rel})
        for label,pat in patterns.items():
            if re.search(pat,b) or re.search(pat,b.replace(b'\0',b'')):
                failures.append({'type':label,'path':rel})
        scanned+=1
    report={'files_scanned':scanned,'manifest_files_verified':len(expected),
            'findings':failures,'runtime_tested':False,
            'scope':'Known local identifiers, paths, credential signatures; plain bytes, UTF-16 and CWS SWF. Not proof of absence of every possible secret.'}
    (root/'dev/manifests/privacy-check.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False,indent=2))
    if failures:raise SystemExit(1)

if __name__=='__main__':main()
