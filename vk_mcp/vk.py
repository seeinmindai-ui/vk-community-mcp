"""Community-bound VK API. No raw endpoint, filesystem or arbitrary URL tools."""
import asyncio
import base64
import json
import secrets
import time
import httpx
from . import catalog,media

READS = {
 'wall': ('wall.get', {'offset','count','filter'}, 'read'),
 'posts': ('wall.getById', {'post_ids'}, 'read'),
 'community': ('groups.getById', {'fields'}, 'read'),
 'members': ('groups.getMembers', {'offset','count','fields','sort'}, 'read'),
 'comments': ('wall.getComments', {'post_id','offset','count','sort','need_likes'}, 'read'),
 'statistics': ('stats.get', {'timestamp_from','timestamp_to','interval'}, 'user'),
 'post_reach': ('stats.getPostReach', {'post_ids'}, 'user'),
 'conversations': ('messages.getConversations', {'offset','count','filter'}, 'message'),
 'history': ('messages.getHistory', {'peer_id','offset','count','start_message_id'}, 'message'),
 'products': ('market.get', {'offset','count'}, 'user'),
}
ACTIONS = {
 'upload_video': ('video.save', {'source_url','name','description'}, {'source_url'}),
 'upload_wall_photo': ('photos.getWallUploadServer', {'image_base64'}, {'image_base64'}),
 'publish_post': ('wall.post', {'message','attachments','publish_date','signed'}, {'message'}),
 'edit_post': ('wall.edit', {'post_id','message','attachments'}, {'post_id','message'}),
 'delete_post': ('wall.delete', {'post_id'}, {'post_id'}),
 'pin_post': ('wall.pin', {'post_id'}, {'post_id'}),
 'unpin_post': ('wall.unpin', {'post_id'}, {'post_id'}),
 'reply_comment': ('wall.createComment', {'post_id','message','reply_to_comment'}, {'post_id','message'}),
 'reply_message': ('messages.send', {'peer_id','message','attachment'}, {'peer_id','message'}),
 'mark_read': ('messages.markAsRead', {'peer_id','start_message_id'}, {'peer_id'}),
}


class VK:
    def __init__(self, store):
        self.store = store
        self.locks = {}
        self.last = {}

    async def call(self, token, method, params, retry_read=False):
        # One queue per credential even when shared by several communities/tenants.
        from .store import digest
        key = digest(token)
        lock = self.locks.setdefault(key, asyncio.Lock())
        async with lock:
            for attempt in range(3 if retry_read else 1):
                await asyncio.sleep(max(0, self.last.get(key,0)+0.36-time.monotonic()))
                self.last[key] = time.monotonic()
                try:
                    async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
                        response = await client.post('https://api.vk.com/method/'+method,
                            data={k: ('1' if v is True else '0' if v is False else ','.join(map(str,v)) if isinstance(v,list) else str(v))
                                  for k,v in {**params,'access_token':token,'v':'5.199'}.items()})
                        response.raise_for_status()
                        data = response.json()
                except (httpx.HTTPError,ValueError):
                    # Never echo request URLs, body, token or VK request_params.
                    raise ValueError('Сеть VK: результат запроса неизвестен. Запись автоматически не повторяется.') from None
                if 'error' not in data:
                    return data.get('response',{})
                code = data['error'].get('error_code',0)
                if code==6 and retry_read and attempt<2:
                    await asyncio.sleep(2**attempt)
                    continue
                hints = {5:'Токен отклонён',7:'Недостаточно прав',15:'Нет доступа',
                         27:'Метод недоступен токену сообщества',14:'VK требует CAPTCHA',
                         1051:'Этот тип токена не разрешает метод',6:'Лимит запросов VK'}
                raise ValueError(f"VK {code}: {hints.get(code,'Вызов отклонён VK')}")

    async def read(self, tenant, alias, operation, params):
        if operation in catalog.METHODS:
            group,creds=self.store.credentials(tenant,alias)
            p=catalog.validate(operation,'read',group,params)
            token,_=catalog.credential(operation,creds)
            return await self.call(token,operation,p,True)
        if operation not in READS:
            raise ValueError('Неизвестная операция чтения')
        method, allowed, mode = READS[operation]
        if set(params)-allowed:
            raise ValueError('Неизвестные параметры')
        group, creds = self.store.credentials(tenant,alias)
        for key in ('count','offset'):
            if key in params and (type(params[key]) is not int or params[key]<0):
                raise ValueError('count и offset должны быть неотрицательными целыми')
        if params.get('count',20)>100:
            raise ValueError('Не более 100 результатов на страницу')
        p = dict(params)
        if operation in ('conversations','history'):
            token = creds['token']
            if operation=='history' and type(p.get('peer_id')) is not int:
                raise ValueError('Нужен peer_id')
        elif mode=='user':
            token = creds.get('user_token')
            if not token:
                raise ValueError('Для операции нужен отдельно подключённый пользовательский токен с нужными правами')
            p['owner_id' if operation!='statistics' else 'group_id'] = -group if operation!='statistics' else group
        else:
            token = creds.get('service_key') or creds.get('user_token')
            if not token:
                raise ValueError('Для публичного чтения подключите сервисный ключ приложения VK')
            if operation in ('community','members'):
                p['group_ids' if operation=='community' else 'group_id'] = group
            elif operation=='posts':
                ids = p.pop('post_ids',[])
                if not isinstance(ids,list) or not ids or len(ids)>100 or any(type(i) is not int or i<=0 for i in ids):
                    raise ValueError('post_ids: от 1 до 100 положительных номеров постов')
                p['posts'] = ','.join(f'-{group}_{i}' for i in ids)
            else:
                p['owner_id'] = -group
        return await self.call(token,method,p,True)

    def prepare(self, tenant, alias, action, params):
        group,_ = self.store.credentials(tenant,alias)
        if action in catalog.METHODS:
            group,creds=self.store.credentials(tenant,alias)
            p=catalog.validate(action,'write',group,params)
            catalog.credential(action,creds)
            if len(json.dumps(p))>24000:raise ValueError('Слишком большой запрос')
            op=secrets.token_urlsafe(32)
            self.store.put('action',op,{'tenant':tenant,'alias':alias,'group_id':group,
                'action':action,'params':p,'approved':False},600)
            return op
        if action not in ACTIONS:
            raise ValueError('Неизвестное действие')
        _,allowed,required = ACTIONS[action]
        if set(params)-allowed or not required.issubset(params):
            raise ValueError('Недопустимые или отсутствующие параметры')
        media_info={}
        if action=='upload_video':
            _,creds=self.store.credentials(tenant,alias)
            if not creds.get('user_token'):raise ValueError('not_configured: video.save требует пользовательский ключ по официальной схеме VK')
            if any(not isinstance(params[k],str) or len(params[k])>16000 for k in ('name','description') if k in params):raise ValueError('Неверное название или описание видео')
            blob,sha=media.download_video(params['source_url'])
            media_info={'media_sha256':sha,'media_bytes':len(blob)}
        if action=='upload_wall_photo':
            image=self.decode_image(params['image_base64'])
        if len(json.dumps(params))>(6*1024*1024 if action=='upload_wall_photo' else 24000):
            raise ValueError('Слишком большой запрос')
        for key in ('post_id','reply_to_comment','peer_id','start_message_id','publish_date'):
            if key in params and (type(params[key]) is not int or params[key]<=0):
                raise ValueError('Нужны положительные целые идентификаторы')
        for key in ('message','attachments','attachment'):
            if key in params and not isinstance(params[key],str):
                raise ValueError('Текст и вложения должны быть строками')
        if params.get('publish_date',int(time.time())+1)<=time.time():
            raise ValueError('Дата отложенной публикации должна быть в будущем')
        op = secrets.token_urlsafe(32)
        self.store.put('action',op,{'tenant':tenant,'alias':alias,'group_id':group,
            'action':action,'params':params,'approved':False,**media_info},600)
        return op

    @staticmethod
    def decode_image(value):
        try:
            data=base64.b64decode(value,validate=True)
        except (ValueError,TypeError):
            raise ValueError('Нужны данные JPEG или PNG в base64 без префикса data:') from None
        if len(data)>4*1024*1024 or not (data.startswith(b'\x89PNG\r\n\x1a\n') or data.startswith(b'\xff\xd8\xff')):
            raise ValueError('Допустим JPEG/PNG размером до 4 МиБ')
        return data

    async def upload_wall_photo(self, group, creds, encoded):
        from urllib.parse import urlsplit
        token=creds.get('user_token')
        if not token:
            raise ValueError('Загрузка фото требует отдельно проверенного пользовательского токена')
        data=self.decode_image(encoded)
        server=await self.call(token,'photos.getWallUploadServer',{'group_id':group})
        url=server.get('upload_url','')
        u=urlsplit(url)
        host=u.hostname or ''
        if u.scheme!='https' or u.username or u.password or u.port not in (None,443) or not any(
            host==d or host.endswith('.'+d) for d in ('vk.com','userapi.com','vkuserphoto.ru','vkuser.net')):
            raise ValueError('VK вернул непроверенный адрес загрузки')
        try:
            async with httpx.AsyncClient(timeout=45,follow_redirects=False) as client:
                r=await client.post(url,files={'photo':('photo.png' if data.startswith(b'\x89PNG') else 'photo.jpg',data)})
                r.raise_for_status(); uploaded=r.json()
        except (httpx.HTTPError,ValueError):
            raise ValueError('Загрузка в VK не подтверждена; автоматического повтора нет') from None
        if not all(k in uploaded for k in ('server','photo','hash')) or uploaded['photo']=='[]':
            raise ValueError('VK не подтвердил загрузку фото')
        photos=await self.call(token,'photos.saveWallPhoto',{'group_id':group,
            **{k:uploaded[k] for k in ('server','photo','hash')}})
        return {'attachments':[f"photo{p['owner_id']}_{p['id']}" for p in photos]}

    async def execute(self, tenant, op):
        obj = self.store.get('action',op)
        if not obj or obj['tenant']!=tenant or not obj['approved']:
            raise ValueError('Действие не подтверждено, истекло или принадлежит другому пользователю')
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute('SELECT status,result FROM writes WHERE tenant=? AND operation=?',(tenant,op)).fetchone()
            if previous:
                if previous['status']=='done':
                    return json.loads(previous['result'])
                raise ValueError('Запрос уже выполнялся. Результат неизвестен; проверьте VK перед новым действием.')
            db.execute('INSERT INTO writes VALUES(?,?,?,?)',(tenant,op,'started','{}'))
        group,creds = self.store.credentials(tenant,obj['alias'])
        if group!=obj['group_id']:
            raise ValueError('Сообщество изменилось после подтверждения')
        action = obj['action']
        method = action if action in catalog.METHODS else ACTIONS[action][0]
        p = dict(obj['params'])
        if action in catalog.METHODS:
            p=catalog.validate(action,'write',group,p)
            token,_=catalog.credential(action,creds)
            if action=='messages.send':p['random_id']=int.from_bytes(secrets.token_bytes(4),'big') & 0x7fffffff
        elif action in ('reply_message','mark_read'):
            token = creds['token']
            if action=='reply_message':
                p['random_id'] = int.from_bytes(secrets.token_bytes(4),'big') & 0x7fffffff
        else:
            token = creds.get('user_token') or creds['token']
            p['owner_id'] = -group
            if action=='publish_post':
                p['from_group'] = 1
                p['guid'] = op
            if action=='reply_comment':
                p['from_group'] = group
        if action=='upload_video':
            blob,sha=await asyncio.to_thread(media.download_video,p['source_url'])
            if sha!=obj.get('media_sha256') or len(blob)!=obj.get('media_bytes'):
                raise ValueError('Видео изменилось после подготовки: нужна новая проверка и подтверждение')
            if not creds.get('user_token'):raise ValueError('not_configured: нужен пользовательский ключ для video.save')
            saved=await self.call(creds['user_token'],'video.save',
                {'group_id':group,'name':p.get('name',''),'description':p.get('description',''),'wallpost':0})
            if not isinstance(saved,dict) or saved.get('owner_id')!=-group or type(saved.get('video_id')) is not int or not saved.get('upload_url'):
                raise ValueError('Результат резервирования видео неизвестен; не повторяйте автоматически')
            await asyncio.to_thread(media.upload_video,saved['upload_url'],blob)
            result={'owner_id':-group,'video_id':saved['video_id'],'attachment':f"video{-group}_{saved['video_id']}",
                'processing':True,'clip_published':False,'wall_post_published':False}
        elif action=='upload_wall_photo':
            result=await self.upload_wall_photo(group,creds,p['image_base64'])
        else:
            result = await self.call(token,method,p)
        with self.store.db() as db:
            # Encrypted result may contain message IDs; no message bodies stored here.
            db.execute('UPDATE writes SET status=?,result=? WHERE tenant=? AND operation=?',
                       ('done',json.dumps(result),tenant,op))
        return result
