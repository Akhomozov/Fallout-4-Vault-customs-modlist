"""Create local MO2 configuration from the public template (Python 3.10+)."""
from pathlib import Path
import argparse

def render(repo, root):
    def q(path):
        return '"' + str(path).replace('\\','/').replace('"','\\"') + '"'
    game = root/'Stock Game Folder'
    template = (repo/'config/ModOrganizer.ini.template').read_text(encoding='utf-8')
    values = {key:q(path) for key,path in {
        'ROOT':root, 'MODS':root/'mods', 'PROFILES':root/'profiles',
        'DOWNLOADS':root/'downloads', 'OVERWRITE':root/'overwrite',
        'GAME':game, 'F4SE':game/'f4se_loader.exe'}.items()}
    values['GAME_BYTES'] = '@ByteArray(' + ''.join('\\x%02x'%b for b in str(game).replace('\\','/').encode('utf-8')) + ')'
    for key,value in values.items():
        template = template.replace('@@'+key+'@@',value)
    assert '@@' not in template
    return template

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root',required=True,type=Path,help='Portable MO2 installation directory')
    parser.add_argument('--check',action='store_true',help='Validate paths only; write nothing')
    args=parser.parse_args()
    root=args.root.resolve()
    repo=Path(__file__).resolve().parents[1]
    # Never configure a working installation in place; this helper targets a new deployment.
    if (root/'ModOrganizer.ini').exists():
        parser.error('ModOrganizer.ini already exists. Review and back it up manually; no files changed.')
    required=[root/'ModOrganizer.exe', root/'Stock Game Folder/Fallout4.exe',
              root/'Stock Game Folder/f4se_loader.exe',root/'profiles/Vault customs RUS/modlist.txt']
    missing=[p.name for p in required if not p.is_file()]
    if missing:
        parser.error('Missing deployment files: '+', '.join(missing))
    text=render(repo,root)
    if args.check:
        print('Deployment paths checked; no files written.')
        return
    for folder in ('mods','downloads','overwrite','profiles'):
        (root/folder).mkdir(exist_ok=True)
    (root/'portable.txt').touch(exist_ok=True)
    with (root/'ModOrganizer.ini').open('x',encoding='utf-8',newline='\n') as f:
        f.write(text)
    assert 'selected_profile=@ByteArray(Vault customs RUS)' in (root/'ModOrganizer.ini').read_text(encoding='utf-8')
    print('Created portable MO2 configuration. Select Play Vault Customs and check game version before launch.')

if __name__=='__main__':
    main()
