import asyncio,base64,hashlib,tempfile,unittest
from urllib.parse import urlsplit,parse_qs
from unittest.mock import AsyncMock
from starlette.testclient import TestClient
from vk_mcp.server import build,Guard
import logging
logging.disable(logging.CRITICAL)
ORIGIN='https://mcp.shmasiki.pro'
PASSWORD='test-only-password-32-characters'

class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.server,self.store,self.provider,self.vk=build(self.temp.name,ORIGIN)
        for u in ['alice','bob']: self.store.user(u,PASSWORD)
        self.store.community('alice','alpha',101,{'token':'fake-group-token','service_key':'fake-service-key'})
        self.store.community('bob','beta',202,{'token':'fake-bob-token'})
        self.client=TestClient(Guard(self.server.streamable_http_app()),base_url=ORIGIN)
        self.client.__enter__()
    def tearDown(self):
        self.client.__exit__(None,None,None)
        self.temp.cleanup()
    def rpc(self,method,params=None,token=None):
        h={'Accept':'application/json, text/event-stream'}
        if token: h['Authorization']='Bearer '+token
        return self.client.post('/vk/mcp',json={'jsonrpc':'2.0','id':1,'method':method,'params':params or {}},headers=h)
    def authorize(self):
        reg=self.client.post('/register',json={'redirect_uris':['https://client.example/callback'],
            'grant_types':['authorization_code','refresh_token'],'response_types':['code'],
            'token_endpoint_auth_method':'none','scope':'vk:read vk:write'})
        self.assertEqual(reg.status_code,201,reg.text)
        cid=reg.json()['client_id']; verifier='a'*64
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        r=self.client.get('/authorize',params={'client_id':cid,'redirect_uri':'https://client.example/callback',
            'response_type':'code','code_challenge':challenge,'code_challenge_method':'S256',
            'scope':'vk:read vk:write','state':'test-state','resource':ORIGIN+'/vk/mcp'},follow_redirects=False)
        self.assertIn(r.status_code,(302,303,307),r.text)
        login=r.headers['location']; ticket=parse_qs(urlsplit(login).query)['ticket'][0]
        self.client.get(login)
        r=self.client.post('/vk/login',data={'ticket':ticket,'csrf':self.client.cookies.get('vk_csrf'),
            'username':'alice','password':PASSWORD},headers={'Origin':ORIGIN},follow_redirects=False)
        self.assertEqual(r.status_code,303,r.text)
        code=parse_qs(urlsplit(r.headers['location']).query)['code'][0]
        d={'grant_type':'authorization_code','client_id':cid,'code':code,
            'redirect_uri':'https://client.example/callback','code_verifier':verifier,'resource':ORIGIN+'/vk/mcp'}
        bad={**d,'code_verifier':'b'*64}
        self.assertEqual(self.client.post('/token',data=bad).status_code,400)
        r=self.client.post('/token',data=d)
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(self.client.post('/token',data=d).status_code,400)
        return r.json(),cid
    def test_oauth_protocol_and_tenant(self):
        self.assertEqual(self.rpc('tools/list').status_code,401)
        self.assertEqual(self.rpc('tools/list',token='invalid').status_code,401)
        tokens,cid=self.authorize(); t=tokens['access_token']
        r=self.rpc('initialize',{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'test','version':'1'}},t)
        self.assertEqual(r.status_code,200,r.text)
        r=self.rpc('tools/call',{'name':'vk_communities','arguments':{}},t).json()
        self.assertIn('alpha',str(r)); self.assertNotIn('beta',str(r))
        self.assertEqual(len(self.rpc('tools/list',token=t).json()['result']['tools']),6)
        r=self.client.post('/token',data={'grant_type':'refresh_token','client_id':cid,
            'refresh_token':tokens['refresh_token'],'scope':'vk:read','resource':ORIGIN+'/vk/mcp'})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(self.rpc('tools/list',token=t).status_code,401)
        r=self.rpc('tools/call',{'name':'vk_prepare_action','arguments':{
            'community':'alpha','action':'publish_post','parameters':{'message':'test'}}},r.json()['access_token']).json()
        self.assertTrue(r['result'].get('isError'))
    def test_encryption_and_isolation(self):
        self.assertNotIn(b'fake-group-token',self.store.path.read_bytes())
        with self.assertRaises(ValueError): self.store.credentials('bob','alpha')
        self.assertTrue(self.store.verify('alice',PASSWORD))
        self.assertFalse(self.store.verify('alice','wrong'))
        self.assertFalse(self.store.verify('nobody',PASSWORD))
    def test_approval_and_idempotency(self):
        op=self.vk.prepare('alice','alpha','publish_post',{'message':'Hello'})
        self.vk.call=AsyncMock(return_value={'post_id':44})
        with self.assertRaises(ValueError): asyncio.run(self.vk.execute('alice',op))
        self.client.get('/vk/approve',params={'ticket':op})
        d={'ticket':op,'csrf':self.client.cookies.get('vk_csrf'),'username':'alice','password':PASSWORD}
        self.assertEqual(self.client.post('/vk/approve',data=d,headers={'Origin':'https://evil.example'}).status_code,403)
        r=self.client.post('/vk/approve',data=d,headers={'Origin':ORIGIN})
        self.assertEqual(r.status_code,200,r.text); self.assertIn('Hello',r.text)
        d.update(csrf=self.client.cookies.get('vk_csrf'),reviewed='yes')
        self.assertEqual(self.client.post('/vk/approve',data=d,headers={'Origin':ORIGIN}).status_code,200)
        for _ in range(2): self.assertEqual(asyncio.run(self.vk.execute('alice',op)),{'post_id':44})
        self.vk.call.assert_awaited_once()
        with self.assertRaises(ValueError): asyncio.run(self.vk.execute('bob',op))
    def test_target_and_parameters(self):
        for action,params in [('publish_post',{'message':'x','owner_id':-202}),('shell',{})]:
            with self.assertRaises(ValueError): self.vk.prepare('alice','alpha',action,params)
        for alias,op,p in [('alpha','wall',{'count':500}),('alpha','statistics',{}),('beta','wall',{})]:
            with self.assertRaises(ValueError): asyncio.run(self.vk.read('alice',alias,op,p))
    def test_image_upload_blocks_untrusted_urls(self):
        from vk_mcp.vk import VK
        payload=base64.b64encode(b'\x89PNG\r\n\x1a\n' + b'fixture').decode()
        self.vk.call=AsyncMock(return_value={'upload_url':'https://127.0.0.1/private'})
        with self.assertRaises(ValueError):
            asyncio.run(self.vk.upload_wall_photo(101,{'user_token':'fake'},payload))
        with self.assertRaises(ValueError): VK.decode_image('/etc/passwd')
        with self.assertRaises(ValueError): VK.decode_image(base64.b64encode(b'hello').decode())
        op=self.vk.prepare('alice','alpha','upload_wall_photo',{'image_base64':payload})
        self.assertFalse(self.store.get('action',op)['approved'])

    def test_expiry(self):
        op=self.vk.prepare('alice','alpha','publish_post',{'message':'Hello'})
        with self.store.db() as db:
            db.execute("UPDATE objects SET expires=0 WHERE kind='action'")
        with self.assertRaises(ValueError): asyncio.run(self.vk.execute('alice',op))
        self.assertIsNone(self.store.get('action',op))

    def test_http_security(self):
        r=self.client.get('/vk/health'); self.assertEqual(r.status_code,200)
        self.assertEqual(r.headers['referrer-policy'],'no-referrer')
        self.assertEqual(r.headers['x-frame-options'],'DENY')
        self.assertEqual(self.client.post('/register',content=b'x'*(6*1024*1024+1)).status_code,413)
        r=self.client.post('/register',json={'redirect_uris':['http://evil.example/callback'],
            'grant_types':['authorization_code','refresh_token'],'response_types':['code']})
        self.assertEqual(r.status_code,400)

if __name__=='__main__': unittest.main()
