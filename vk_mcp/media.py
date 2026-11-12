"""Bounded public HTTPS media with DNS pinning. No local files or proxy use."""
import hashlib
import http.client
import ipaddress
import json
import secrets
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor,TimeoutError as FutureTimeout
import ssl
from urllib.parse import urlsplit,urljoin

MAX_BYTES=20*1024*1024
_DNS_POOL=ThreadPoolExecutor(max_workers=4,thread_name_prefix='vk-media-dns')
_DNS_SLOTS=threading.BoundedSemaphore(4)


def resolve(host):
    if not _DNS_SLOTS.acquire(blocking=False):raise ValueError('Слишком много запросов DNS')
    try:future=_DNS_POOL.submit(socket.getaddrinfo,host,443,type=socket.SOCK_STREAM)
    except BaseException:_DNS_SLOTS.release();raise
    future.add_done_callback(lambda _: _DNS_SLOTS.release())
    try:return future.result(timeout=10)
    except FutureTimeout:raise ValueError('Превышено время DNS') from None

UPLOAD_HOSTS=('vk.com','userapi.com','vkuserphoto.ru','vkuserlive.net')


def public_address(value):
    try:
        ip=ipaddress.ip_address(value)
        return ip.is_global and not ip.is_multicast and not ip.is_unspecified and not getattr(ip,'ipv4_mapped',None) and not getattr(ip,'sixtofour',None) and not getattr(ip,'teredo',None)
    except ValueError:return False


def target(value,upload=False):
    try:
        if not isinstance(value,str) or len(value)>8192 or any(ord(c)<33 for c in value):raise ValueError()
        u=urlsplit(value)
        host=u.hostname
        if u.scheme!='https' or not host or u.username or u.password or u.fragment or u.port not in (None,443) or host.endswith('.') or '%' in host:raise ValueError()
        if host=='localhost' or host.endswith(('.localhost','.local')):raise ValueError()
        if upload and not any(host==h or host.endswith('.'+h) for h in UPLOAD_HOSTS):raise ValueError()
        answers=resolve(host)
        if not answers or any(not public_address(r[4][0]) for r in answers):raise ValueError()
        return u,answers[0][4][0]
    except (ValueError,OSError):raise ValueError('Адрес медиа недоступен или не разрешён') from None


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self,host,address):
        super().__init__(host,timeout=30,context=ssl.create_default_context())
        self.address=address
    def connect(self):
        sock=socket.create_connection((self.address,443),self.timeout)
        try:self.sock=self._context.wrap_socket(sock,server_hostname=self.host)
        except BaseException:sock.close();raise


def exchange(url,method='GET',body=None,headers=None,upload=False):
    u,address=target(url,upload)
    connection=PinnedHTTPS(u.hostname,address)
    try:
        connection.request(method,u.path or '/' if not u.query else (u.path or '/')+'?'+u.query,body=body,headers=headers or {})
        response=connection.getresponse()
        status=response.status; meta={k.lower():v for k,v in response.getheaders()}
        limit=1024*1024 if upload else MAX_BYTES
        if status in (301,302,303,307,308):return status,meta,b''
        if status!=200:raise ValueError('HTTP медиа: запрос отклонён')
        length=meta.get('content-length')
        if length is not None and (not length.isdigit() or int(length)>limit):raise ValueError('Превышен размер медиа')
        chunks=[];total=0;deadline=time.monotonic()+30
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise ValueError('Превышено время чтения медиа')
            if connection.sock is not None:connection.sock.settimeout(remaining)
            chunk=response.read1(min(65536,limit+1-total))
            if not chunk:break
            total+=len(chunk)
            if total>limit:raise ValueError('Превышен размер медиа')
            chunks.append(chunk)
        data=b''.join(chunks)
        return status,meta,data
    except (OSError,http.client.HTTPException):raise ValueError('Сеть медиа: запрос не завершён') from None
    finally:connection.close()


def download_video(url):
    for attempt in range(4):
        status,headers,data=exchange(url)
        if status in (301,302,303,307,308):
            if attempt==3 or not headers.get('location'):raise ValueError('Слишком много перенаправлений медиа')
            url=urljoin(url,headers['location']);continue
        if headers.get('content-type','').split(';')[0].strip().lower()!='video/mp4':raise ValueError('Нужен MP4 с типом video/mp4')
        if not 12<=len(data)<=MAX_BYTES or data[4:8]!=b'ftyp':raise ValueError('Не распознан контейнер MP4')
        return data,hashlib.sha256(data).hexdigest()
    raise ValueError('Медиа недоступно')


def upload_video(url,data):
    boundary='vkmedia'+secrets.token_hex(24)
    body=(f'--{boundary}\r\nContent-Disposition: form-data; name="video_file"; filename="video.mp4"\r\nContent-Type: video/mp4\r\n\r\n'.encode()+data+f'\r\n--{boundary}--\r\n'.encode())
    status,_,response=exchange(url,'POST',body,{'Content-Type':'multipart/form-data; boundary='+boundary},True)
    if status!=200:raise ValueError('Переадресация загрузки запрещена')
    try:result=json.loads(response)
    except ValueError:raise ValueError('Некорректный ответ загрузки') from None
    if not isinstance(result,dict) or 'error' in result or result.get('response')==0:raise ValueError('Загрузка видео отклонена')
    return result
