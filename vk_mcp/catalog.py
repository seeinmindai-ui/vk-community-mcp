"""Pinned teacher catalog; execution remains tenant-bound and owner-approved.
Metadata provenance and MIT notices: THIRD_PARTY_NOTICES.md.
"""
import copy
import json
import math
from pathlib import Path

SOURCE_COMMIT = '1ca3b0b4be8cbe7ce23984f3d209416107440554'
METHODS = {m['name']:m for m in json.loads(Path(__file__).with_name('methods.json').read_text())}


def describe(name):
    if name not in METHODS:
        raise ValueError('Метод отсутствует в проверенном каталоге')
    return copy.deepcopy(METHODS[name])


def valid_value(spec, value):
    types=spec.get('type'); types=types if isinstance(types,list) else [types]
    checks={'integer':type(value) is int and abs(value)<=2**53-1,
            'number':type(value) in (int,float) and math.isfinite(value),
            'string':isinstance(value,str),'boolean':type(value) is bool or type(value) is int and value in (0,1),
            'array':isinstance(value,list)}
    if not any(checks.get(t,False) for t in types):return False
    if type(value) in (int,float):
        if value<spec.get('minimum',-math.inf) or value>spec.get('maximum',math.inf):return False
    if isinstance(value,str):
        if not spec.get('minLength',0)<=len(value)<=min(spec.get('maxLength',16000),16000):return False
        if any(ord(c)<32 and c not in '\n\r\t' for c in value):return False
    if 'enum' in spec and value not in spec['enum']:return False
    if isinstance(value,list):
        if not spec.get('minItems',0)<=len(value)<=min(spec.get('maxItems',100),100):return False
        item=spec.get('items',{})
        if not item.get('type') or any(not valid_value(item,v) for v in value):return False
    return True


def validate(name, mode, group, params):
    m=describe(name)
    if m['mode']!=mode:raise ValueError('Неверный режим: запись требует подготовки и подтверждения')
    if not isinstance(params,dict) or len(params)>40:raise ValueError('Недопустимые параметры')
    fields={p['name']:p for p in m['parameters']}
    p=copy.deepcopy(params)
    scope=m['scope']; expected=-group if scope=='owner_id' else group
    if scope in p and (type(p[scope]) is not int or p[scope]!=expected):
        raise ValueError('Нельзя сменить выбранное сообщество')
    p[scope]=expected
    if name=='video.delete':p.setdefault('target_id',-group)
    if name=='wall.post':p.setdefault('from_group',True)
    if name=='wall.createComment':p.setdefault('from_group',group)
    for key,value in p.items():
        if key not in fields or key in ('access_token','v','execute','random_id') or not valid_value(fields[key],value):
            raise ValueError('Неизвестный или недопустимый параметр: '+key)
    if any(s.get('required') and k not in p for k,s in fields.items()):raise ValueError('Не заполнены обязательные параметры')
    if 'count' in p and not 0<=p['count']<=100:raise ValueError('Не более100 объектов на страницу')
    if name.startswith('messages.'):
        if 'peer_id' in p and (type(p['peer_id']) is not int or p['peer_id']<=0):raise ValueError('Недопустимый диалог')
        if name in ('messages.edit','messages.delete') and 'peer_id' not in p:raise ValueError('Нужен диалог сообщества')
    if name=='messages.edit' and ('cmid' not in p or not any(p.get(k) for k in ('message','attachment'))):raise ValueError('Нужен локальный ID и новый текст/вложение')
    if name=='messages.delete' and not p.get('cmids'):raise ValueError('Нужны локальные ID сообщений')
    if name in ('groups.ban','groups.unban') and (type(p.get('owner_id')) is not int or p['owner_id']<=0):raise ValueError('Нужен ID пользователя')
    if name=='video.delete' and p['target_id']!=-group:raise ValueError('Нельзя удалить видео из другого сообщества')
    if name=='photos.get' and 'photo_ids' in p:
        if any(not isinstance(x,str) or not x.isascii() or not x.isdigit() or not 0<int(x)<=2**53-1 for x in p['photo_ids']):raise ValueError('Нужны ID фото внутри выбранного сообщества')
    if name=='wall.post' and p.get('from_group') not in (True,1):raise ValueError('Пост только от сообщества')
    if name=='wall.createComment' and p.get('from_group')!=group:raise ValueError('Комментарий только от выбранного сообщества')
    return p


def credential(method, creds):
    types=METHODS[method]['tokenTypes']
    # Community inbox must never fall back to a personal token.
    order=['group'] if method.startswith('messages.') else ['group','user','service']
    for kind in order:
        value=creds.get({'group':'token','user':'user_token','service':'service_key'}[kind])
        if kind in types and value and (kind!='service' or METHODS[method]['mode']=='read'):
            return value,kind
    raise ValueError('not_configured: не подключён подходящий тип ключа: '+', '.join(types))


def readiness(creds):
    result=[]
    for name,m in METHODS.items():
        try:_,kind=credential(name,creds); ready=True
        except ValueError:kind=None;ready=False
        result.append({'method':name,'mode':m['mode'],'token_types':m['tokenTypes'],
                       'credential_configured':ready,'selected_type':kind,'vk_access_verified':False})
    return result
