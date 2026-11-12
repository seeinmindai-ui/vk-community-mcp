#!/usr/bin/env python3
"""Install checked public production commits; no GitHub or deploy secrets."""
import fcntl,hashlib,io,json,os,pathlib,re,shutil,subprocess,time,urllib.request,zipfile
REPO='seeinmindai-ui/vk-community-mcp'
BASE=pathlib.Path('/opt/mcp/vk')
USER='mcp-vk-build'


def fetch(url,maximum):
    request=urllib.request.Request(url,headers={'User-Agent':'VK-Community-MCP-Updater/0.1'})
    with urllib.request.urlopen(request,timeout=30) as response:
        value=response.read(maximum+1)
    if len(value)>maximum: raise RuntimeError('Download limit exceeded')
    return value


def run(cmd,cwd=None,build=False):
    if build: cmd=['/usr/sbin/runuser','-u',USER,'--']+cmd
    result=subprocess.run(cmd,cwd=cwd,capture_output=True,text=True,timeout=300,
        env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':'/var/lib/mcp-vk-build','PYTHONDONTWRITEBYTECODE':'1',
             'PIP_DISABLE_PIP_VERSION_CHECK':'1','PYTHONUNBUFFERED':'1'})
    if result.returncode: raise RuntimeError('Update check failed: '+str(cmd[-3:])+'; '+result.stderr[-1200:])
    return result.stdout


def main():
    BASE.mkdir(parents=True,exist_ok=True)
    with (BASE/'update.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        ref=json.loads(fetch('https://api.github.com/repos/'+REPO+'/git/ref/heads/production',65536))
        sha=ref['object']['sha']
        if not re.fullmatch('[0-9a-f]{40}',sha): raise RuntimeError('Invalid commit')
        state=BASE/'deployed.json'
        if state.exists() and json.loads(state.read_text()).get('commit')==sha:
            print('Already current');return
        release=BASE/'releases'/sha
        if release.exists():
            # Never execute or overwrite a partially built tree on retry.
            raise RuntimeError('Release directory already exists; review before retry')
        release.mkdir(parents=True,mode=0o755)
        data=fetch('https://codeload.github.com/'+REPO+'/zip/'+sha,10*1024*1024)
        archive=zipfile.ZipFile(io.BytesIO(data))
        if sum(x.file_size for x in archive.infolist())>30*1024*1024: raise RuntimeError('Archive limit')
        for item in archive.infolist():
            parts=pathlib.PurePosixPath(item.filename).parts[1:]
            if not parts: continue
            if '..' in parts or any(p.startswith('/') for p in parts) or (item.external_attr>>16)&0o170000==0o120000:
                raise RuntimeError('Unsafe archive')
            dest=release.joinpath(*parts)
            if item.is_dir():dest.mkdir(parents=True,exist_ok=True);continue
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(archive.read(item))
        lines=(release/'requirements.lock').read_text().splitlines()
        if not lines or any(not re.fullmatch(r'[A-Za-z0-9_.-]+==[A-Za-z0-9_.+!-]+',line) for line in lines):
            raise RuntimeError('Only exact PyPI requirements allowed')
        run(['chown','-R',USER+':'+USER,str(release)])
        python=str(release/'.venv/bin/python')
        run(['python3','-m','venv',str(release/'.venv')],cwd=release,build=True)
        run([python,'-m','pip','install','-r','requirements.lock'],cwd=release,build=True)
        run([python,'-m','pip','install','--no-deps','.'],cwd=release,build=True)
        run([python,'-B','-m','unittest','discover','-s','tests','-v'],cwd=release,build=True)
        run([python,'scripts/check_publication.py'],cwd=release,build=True)
        # Freeze code ownership before starting the service. chown -h does not follow links.
        run(['chown','-hR','root:root',str(release)])
        current=BASE/'current'; previous=str(current.resolve()) if current.exists() else None
        next_link=BASE/'current.next'
        if next_link.is_symlink():next_link.unlink()
        next_link.symlink_to(release);os.replace(next_link,current)
        try:
            run(['systemctl','restart','vk-community'])
            for _ in range(20):
                try:
                    result=json.loads(fetch('http://127.0.0.1:8310/vk/health',4096))
                    if result.get('status')=='ok':break
                except Exception:time.sleep(.5)
            else:raise RuntimeError('Health check failed')
        except Exception:
            if previous:
                next_link.symlink_to(previous);os.replace(next_link,current)
                run(['systemctl','restart','vk-community'])
            raise
        state.write_text(json.dumps({'commit':sha,'previous':previous,'release':str(release)}))
        print('Deployed '+sha)

if __name__=='__main__':main()
