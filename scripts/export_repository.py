"""Export an explicitly selected MO2 profile; never edit the source installation."""
from pathlib import Path
import argparse, hashlib, json, re, struct, zlib

PROFILE = 'Vault customs RUS'
PROFILE_FILES = ['modlist.txt', 'plugins.txt', 'loadorder.txt', 'archives.txt',
                 'lockedorder.txt', 'settings.ini', 'fallout4.ini',
                 'fallout4custom.ini', 'fallout4prefs.ini', 'initweaks.ini']
RUNTIME_DIRS = {'f4se', 'mcm', 'interface', 'scripts', 'meshes', 'textures',
                'materials', 'sound', 'strings', 'seq', 'vis', 'music'}
RUNTIME_EXTS = {'.dll', '.ini', '.json', '.txt', '.esp', '.esm', '.esl', '.ba2',
                '.pex', '.nif', '.hkx', '.dds', '.bgsm', '.bgem', '.swf',
                '.strings', '.dlstrings', '.ilstrings', '.wav', '.xwm', '.seq'}

def sha(b):
    return hashlib.sha256(b).hexdigest()

def pex_clean(data):
    assert data[:4] == bytes.fromhex('dec057fa'), 'Unexpected PEX format'
    data = bytearray(data)
    pos = 16
    for i in range(3):
        length = struct.unpack_from('<H', data, pos)[0]
        pos += 2
        value = bytes(data[pos:pos+length])
        clean = value.replace(b'\\', b'/').split(b'/')[-1] if i == 0 else b'public'
        clean = clean[:length].ljust(length, b'_')
        data[pos:pos+length] = clean
        pos += length
    return bytes(data), pos

def dll_clean(data):
    """Sanitize diagnostic ASCII paths only; assert that code sections are identical."""
    new = bytearray(data)
    for m in re.finditer(rb'(?:[A-Za-z]:\\Modlists\\|[A-Za-z]:\\Users\\)[\x20-\x7e]+', data):
        value = m.group()
        clean = b'release/' + re.split(rb'[\\/]', value)[-1]
        new[m.start():m.end()] = clean[:len(value)].ljust(len(value), b'_')
    wide_path = rb'[A-Za-z]\x00:\x00\\\x00U\x00s\x00e\x00r\x00s\x00\\\x00(?:[\x20-\x7e]\x00)+'
    for m in re.finditer(wide_path, data):
        value = m.group().decode('utf-16-le')
        clean = 'release/' + re.split(r'[\\/]', value)[-1]
        new[m.start():m.end()] = clean[:len(value)].ljust(len(value),'_').encode('utf-16-le')
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[pe:pe+4] == b'PE\0\0'
    count = struct.unpack_from('<H', data, pe+6)[0]
    table = pe+24+struct.unpack_from('<H', data, pe+20)[0]
    for i in range(count):
        off = table+i*40
        size, start = struct.unpack_from('<II', data, off+16)
        flags = struct.unpack_from('<I', data, off+36)[0]
        if flags & 0x20000000:
            assert data[start:start+size] == new[start:start+size], 'Code changed'
    assert len(new) == len(data)
    return bytes(new)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    repo = Path(__file__).resolve().parents[1]
    assert source != repo and (source/'ModOrganizer.ini').is_file()
    # Re-export must be reviewed rather than silently leave stale files in the package.
    assert not (repo/'mods').exists(), 'mods already exists; use a fresh export directory'
    before_mo = sha((source/'ModOrganizer.ini').read_bytes())
    inputs, files, excluded, changes = [], [], [], []
    def write(rel, raw, data=None, reason=None):
        out = repo/rel
        out.parent.mkdir(parents=True, exist_ok=True)
        data = raw if data is None else data
        out.write_bytes(data)
        row = {'path': rel.as_posix(), 'bytes': len(data), 'sha256': sha(data),
               'source_sha256': sha(raw)}
        files.append(row)
        if data != raw:
            changes.append({'path': rel.as_posix(), 'reason': reason})
    profile = source/'profiles'/PROFILE
    for name in PROFILE_FILES:
        raw = (profile/name).read_bytes()
        inputs.append((profile/name, sha(raw)))
        data = raw
        if name.lower() in ('fallout4.ini', 'fallout4custom.ini'):
            data = re.sub(rb'(?im)^sScreenShotBaseName=[^\r\n]*',
                          b'sScreenShotBaseName=ScreenShot', raw)
        write(Path('profiles')/PROFILE/name, raw, data, 'relative screenshot path')
    active = [line[1:] for line in (profile/'modlist.txt').read_text(encoding='utf-8-sig').splitlines()
              if line.startswith('+Vault_customs')]
    all_mods = sorted(p.name for p in (source/'mods').glob('Vault_customs*') if p.is_dir())
    for name in active:
        for p in sorted((source/'mods'/name).rglob('*')):
            if not p.is_file():
                continue
            assert not p.is_symlink()
            rel = p.relative_to(source)
            sub = p.relative_to(source/'mods'/name)
            why = None
            if '.bak' in p.name.lower() or p.suffix.lower() in {'.pdb', '.log', '.tmp', '.mohidden'}:
                why = 'backup/debug/cache'
            elif len(sub.parts) == 1 and p.suffix.lower() not in {'.esp', '.esm', '.esl', '.ba2'}:
                why = 'MO2 metadata or development document'
            elif len(sub.parts) > 1 and (sub.parts[0].lower() not in RUNTIME_DIRS or
                 any(x.lower() in {'source', 'user', 'optional', '_original'} for x in sub.parts[:-1])):
                why = 'source/optional/original material'
            elif p.suffix.lower() not in RUNTIME_EXTS:
                why = 'not a runtime extension'
            if why:
                excluded.append({'path': rel.as_posix(), 'reason': why, 'bytes': p.stat().st_size})
                continue
            raw = p.read_bytes()
            inputs.append((p, sha(raw)))
            data = raw
            if p.suffix.lower() == '.pex':
                data, end = pex_clean(raw)
                assert data[end:] == raw[end:] and len(data) == len(raw)
            elif p.suffix.lower() == '.dll':
                data = dll_clean(raw)
            write(rel, raw, data, 'PEX header metadata' if p.suffix.lower()=='.pex' else 'DLL diagnostic paths')
    assert all(sha(p.read_bytes()) == h for p,h in inputs), 'Source changed during export'
    assert before_mo == sha((source/'ModOrganizer.ini').read_bytes())
    manifest = {'profile': PROFILE, 'active_vault_customs': active,
                'excluded_inactive_mods': [x for x in all_mods if x not in active],
                'runtime_bytes': sum(x['bytes'] for x in files if x['path'].startswith('mods/')),
                'files': files, 'excluded': excluded, 'sanitized': changes,
                'source_files_unchanged': True, 'runtime_tested': False,
                'redistribution_rights_reviewed': False}
    (repo/'manifests').mkdir(exist_ok=True)
    (repo/'manifests/export.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:manifest[k] for k in ('runtime_bytes','source_files_unchanged')},indent=2))
    print(f'Mods: {len(active)}, exported files: {len(files)}, excluded: {len(excluded)}, sanitized: {len(changes)}')

if __name__ == '__main__':
    main()
