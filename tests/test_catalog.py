import asyncio
import json
import unittest
from unittest.mock import AsyncMock
import test_service as support
from vk_mcp import catalog


class CatalogTest(unittest.TestCase):
    def test_complete_pinned_catalog_and_public_descriptions(self):
        self.assertEqual(len(catalog.METHODS),100)
        self.assertEqual({m['mode'] for m in catalog.METHODS.values()},{'read','write'})
        for name,m in catalog.METHODS.items():
            self.assertIn(m['scope'],{'owner_id','group_id'})
            self.assertIn(m['scope'],{p['name'] for p in m['parameters']})
            self.assertNotIn('access_token',{p['name'] for p in m['parameters']})
        copy=catalog.describe('video.get');copy['tokenTypes'].clear()
        self.assertTrue(catalog.METHODS['video.get']['tokenTypes'])

    def test_scoping_types_and_injected_credentials(self):
        self.assertEqual(catalog.validate('video.get','read',101,{'count':10})['owner_id'],-101)
        for field,value in [('owner_id',-202),('access_token','injected'),('count',True),('count',101),('videos',['1_2'])]:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):catalog.validate('video.get','read',101,{field:value})
        with self.assertRaises(ValueError):catalog.validate('video.delete','read',101,{'video_id':1})
        with self.assertRaises(ValueError):catalog.validate('execute','read',101,{})
        with self.assertRaises(ValueError):catalog.validate('video.delete','write',101,{'video_id':1,'target_id':-202})
        with self.assertRaises(ValueError):catalog.validate('photos.get','read',101,{'photo_ids':['-202_1']})
        for text in ['Обычный текст','Видео: история @автор','Строка1\nСтрока2']:
            self.assertTrue(catalog.valid_value({'type':'string'},text))
        self.assertFalse(catalog.valid_value({'type':'string'},'bad\x00text'))

    def test_credentials_fail_closed(self):
        creds={'token':'fake-group','service_key':'fake-service','user_token':'fake-user'}
        self.assertEqual(catalog.credential('messages.getHistory',creds)[1],'group')
        with self.assertRaises(ValueError):catalog.credential('messages.getHistory',{'user_token':'fake-user'})
        with self.assertRaises(ValueError):catalog.credential('stats.get',{'token':'fake-group','service_key':'fake-service'})
        self.assertEqual(catalog.credential('video.get',{'service_key':'fake-service'})[1],'service')
        rows=catalog.readiness({'service_key':'fake-service'})
        self.assertEqual(len(rows),100)
        self.assertTrue(all(not r['vk_access_verified'] for r in rows))
        self.assertNotIn('fake-service',json.dumps(rows))


class CatalogFlowTest(unittest.TestCase):
    setUp=support.ServiceTest.setUp
    tearDown=support.ServiceTest.tearDown
    def test_catalog_reads_and_confirmed_writes(self):
        self.vk.call=AsyncMock(return_value={'items':[]})
        asyncio.run(self.vk.read('alice','alpha','video.get',{'count':1}))
        self.assertEqual(self.vk.call.await_args.args[2]['owner_id'],-101)
        with self.assertRaises(ValueError):asyncio.run(self.vk.read('alice','beta','video.get',{}))
        # User-token-only write must not silently fall back to a group key.
        with self.assertRaises(ValueError):self.vk.prepare('alice','alpha','video.delete',{'video_id':1})
        op=self.vk.prepare('alice','alpha','wall.closeComments',{'post_id':123})
        self.vk.call.reset_mock()
        with self.assertRaises(ValueError):asyncio.run(self.vk.execute('alice',op))
        self.vk.call.assert_not_awaited()
        obj=self.store.get('action',op);obj['approved']=True;self.store.put('action',op,obj,600)
        asyncio.run(self.vk.execute('alice',op));asyncio.run(self.vk.execute('alice',op))
        self.assertEqual(self.vk.call.await_count,1)
        self.assertEqual(self.vk.call.await_args.args[1],'wall.closeComments')
        self.assertEqual(self.vk.call.await_args.args[2]['owner_id'],-101)

    def test_video_status_owner_is_pinned(self):
        self.vk.call=AsyncMock(return_value={'items':[{'id':12,'owner_id':-101,'processing':1}]})
        result=asyncio.run(self.vk.read('alice','alpha','videos_by_id',{'video_ids':[12]}))
        self.assertEqual(self.vk.call.await_args.args[2],{'videos':'-101_12'})
        self.assertEqual(result['items'][0]['processing'],1)
        for value in [['-202_12'],[-12],[True],[]]:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):asyncio.run(self.vk.read('alice','alpha','videos_by_id',{'video_ids':value}))
