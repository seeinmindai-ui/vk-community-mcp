"""Scan only this public source tree. No environment, Keychain or auth files read."""
import json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
EXCLUDED={'.git','__pycache__','.venv','build','dist'}
PATTERNS=[r'vk[12]\.[A-Za-z0-9_-]{24,}',r'gh[pousr]_[A-Za-z0-9]{20,}',
 r'github_pat_[A-Za-z0-9_]{30,}',r'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----',
 r'(?i)(?:password|access_token|client_secret|service_key)\s*[:=]\s*[\"\x27]([^\"\x27\n]{16,})[\"\x27]']

def scan():
    issues=[]; files=[]
    for p in sorted(ROOT.rglob('*')):
        if any(x in EXCLUDED for x in p.relative_to(ROOT).parts) or not p.is_file(): continue
        rel=str(p.relative_to(ROOT))
        if p.suffix in ('.key','.sqlite','.db','.pem') or p.name in ('.env','auth.json','config.toml'):
            issues.append({'path':rel,'reason':'forbidden_file'})
            continue
        try: s=p.read_text()
        except UnicodeDecodeError:
            issues.append({'path':rel,'reason':'unexpected_binary'});continue
        for pattern in PATTERNS:
            for match in re.finditer(pattern,s):
                # Explicit synthetic fixtures only; do not suppress arbitrary secret-looking values.
                value=match.group(0)
                if ('test-only-' in value or 'fake-' in value) and rel=='tests/test_service.py': continue
                issues.append({'path':rel,'line':s.count('\n',0,match.start())+1,'reason':'potential_secret'})
        files.append(rel)
    return {'files':files,'issues':issues}

if __name__=='__main__':
    result=scan();print(json.dumps(result,ensure_ascii=False,indent=2));sys.exit(bool(result['issues']))
