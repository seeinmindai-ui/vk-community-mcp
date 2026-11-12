"""JSON provisioning through stdin; no credentials in arguments."""
import argparse,json,os,sys
from .store import Store

def main():
    p=argparse.ArgumentParser()
    p.add_argument('action',choices=['user','community','status'])
    action=p.parse_args().action
    os.umask(0o077)
    s=Store(os.environ.get('VK_MCP_STATE','/var/lib/mcp-vk'))
    if action=='status':
        with s.db() as db:
            print(json.dumps({k:db.execute('SELECT COUNT(*) FROM '+k).fetchone()[0] for k in ['users','communities']}))
        return
    d=json.load(sys.stdin)
    if action=='user': s.user(d['username'],d['password'])
    else: s.community(d['username'],d['alias'],int(d['group_id']),{k:d[k] for k in ['token','service_key','user_token'] if d.get(k)})
    print(json.dumps({'status':'configured','action':action}))

if __name__=='__main__':
    try: main()
    except Exception:
        print('Настройка отклонена; секретные подробности скрыты',file=sys.stderr)
        raise SystemExit(2)
