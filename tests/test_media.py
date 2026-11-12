import asyncio
import hashlib
import unittest
from unittest.mock import patch,AsyncMock
import test_service as support
from vk_mcp import media

MP4=b'\x00\x00\x00\x18ftypisom'+b'fake-video'

class MediaTest(unittest.TestCase):
    def test_private_and_mixed_dns_rejected(self):
        for address in ['127.0.0.1','10.1.1.1','169.254.169.254','::1','::ffff:8.8.8.8','2002:0808:0808::1','224.0.0.1']:
            self.assertFalse(media.public_address(address))
        with patch.object(media.socket,'getaddrinfo',return_value=[(2,1,6,'',('8.8.8.8',443)),(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaises(ValueError):media.target('https://example.com/video.mp4')
        for url in ['file:///tmp/video.mp4','http://example.com/video.mp4','https://user:pass@example.com/a','https://example.com:8443/a','https://localhost/a','https://example.com/a#fragment','https://example.com\r\nx']:
            with self.assertRaises(ValueError):media.target(url)
        with self.assertRaises(ValueError):media.target('https://vk.com.evil.example/upload',True)

    def test_download_validation_and_redirects(self):
        with patch.object(media,'exchange',return_value=(200,{'content-type':'video/mp4'},MP4)):
            blob,sha=media.download_video('https://example.com/video.mp4')
            self.assertEqual(blob,MP4);self.assertEqual(sha,hashlib.sha256(MP4).hexdigest())
        for mime,blob in [('video/mp4',b'not-mp4'),('text/html',MP4),('video/mp4',MP4+b'x'*media.MAX_BYTES)]:
            with patch.object(media,'exchange',return_value=(200,{'content-type':mime},blob)):
                with self.assertRaises(ValueError):media.download_video('https://example.com/a')
        with patch.object(media,'exchange',return_value=(302,{'location':'/again'},b'')) as request:
            with self.assertRaises(ValueError):media.download_video('https://example.com/a')
            self.assertEqual(request.call_count,4)
        with patch.object(media,'exchange',return_value=(302,{'location':'https://elsewhere.example'},b'')) as request:
            with self.assertRaises(ValueError):media.upload_video('https://upload.vk.com/path',MP4)
            self.assertEqual(request.call_count,1)

class MediaFlowTest(unittest.TestCase):
    def setUp(self):
        support.ServiceTest.setUp(self)
        self.store.community('alice','alpha',101,{'token':'fake-group-token','user_token':'fake-user-token'})
    tearDown=support.ServiceTest.tearDown

    def test_upload_consent_hash_and_result(self):
        sha=hashlib.sha256(MP4).hexdigest()
        self.vk.call=AsyncMock(return_value={'owner_id':-101,'video_id':999,'upload_url':'https://upload.vk.com/path'})
        with patch('vk_mcp.media.download_video',return_value=(MP4,sha)):
            op=self.vk.prepare('alice','alpha','upload_video',{'source_url':'https://example.com/video.mp4','description':'Видео'})
            self.vk.call.assert_not_awaited()
            with self.assertRaises(ValueError):asyncio.run(self.vk.execute('alice',op))
            obj=self.store.get('action',op);obj['approved']=True;self.store.put('action',op,obj,600)
            with patch('vk_mcp.media.upload_video',return_value={}) as upload:
                result=asyncio.run(self.vk.execute('alice',op))
                self.assertEqual(result['attachment'],'video-101_999')
                self.assertTrue(result['processing']);self.assertFalse(result['clip_published'])
                self.assertNotIn('upload_url',result)
                self.assertEqual(asyncio.run(self.vk.execute('alice',op)),result)
                upload.assert_called_once()
                self.assertEqual(self.vk.call.await_args.args[2]['wallpost'],0)

    def test_changed_media_never_reaches_vk(self):
        self.vk.call=AsyncMock()
        with patch('vk_mcp.media.download_video',return_value=(MP4,'original')):
            op=self.vk.prepare('alice','alpha','upload_video',{'source_url':'https://example.com/video.mp4'})
        obj=self.store.get('action',op);obj['approved']=True;self.store.put('action',op,obj,600)
        with patch('vk_mcp.media.download_video',return_value=(MP4,'changed')):
            with self.assertRaises(ValueError):asyncio.run(self.vk.execute('alice',op))
            self.vk.call.assert_not_awaited()
            with self.assertRaises(ValueError):asyncio.run(self.vk.execute('alice',op))
