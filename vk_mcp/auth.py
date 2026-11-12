"""SDK-managed OAuth 2.1 (PKCE/DCR), persistent opaque tokens and consent."""
import secrets
import time
from urllib.parse import urlsplit
from mcp.server.auth.provider import (AccessToken, AuthorizationCode, RefreshToken,
    AuthorizationParams, AuthorizeError, RegistrationError, TokenError)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

SCOPES = ['vk:read', 'vk:write']


class Provider:
    def __init__(self, store, origin):
        self.store, self.origin = store, origin.rstrip('/')
        self.resource = self.origin + '/vk/mcp'

    async def get_client(self, client_id):
        obj = self.store.get('client',client_id)
        return OAuthClientInformationFull.model_validate(obj) if obj else None

    async def register_client(self, client_info):
        for uri in client_info.redirect_uris:
            u = urlsplit(str(uri))
            if u.fragment or u.username or u.password or not (u.scheme=='https' or
                (u.scheme=='http' and u.hostname in ('127.0.0.1','localhost','::1'))):
                raise RegistrationError('invalid_redirect_uri','Нужен HTTPS или loopback redirect')
        with self.store.db() as db:
            if db.execute("SELECT COUNT(*) FROM objects WHERE kind='client'").fetchone()[0] >= 1000:
                raise RegistrationError('invalid_client_metadata','Лимит регистраций')
        self.store.put('client', client_info.client_id, client_info.model_dump(mode='json'), 10*365*86400)

    async def authorize(self, client, params: AuthorizationParams):
        if params.resource not in (None,self.resource):
            raise AuthorizeError('invalid_request','Другой ресурс')
        if not params.code_challenge or len(params.code_challenge)!=43:
            raise AuthorizeError('invalid_request','Нужен PKCE S256')
        scopes = params.scopes or ['vk:read']
        if not set(scopes).issubset(SCOPES):
            raise AuthorizeError('invalid_scope','Неизвестные права')
        ticket = secrets.token_urlsafe(32)
        self.store.put('pending', ticket, {'client_id':client.client_id,
            'client_name':client.client_name or client.client_id,
            'params':params.model_dump(mode='json')}, 600)
        return self.origin+'/vk/login?ticket='+ticket

    async def load_authorization_code(self, client, authorization_code):
        obj = self.store.get('code',authorization_code)
        if not obj or obj['client_id']!=client.client_id:
            return None
        return AuthorizationCode.model_validate(obj)

    async def exchange_authorization_code(self, client, authorization_code):
        obj = self.store.get('code',authorization_code.code,consume=True)
        if not obj or obj['client_id']!=client.client_id:
            raise TokenError('invalid_grant','Код уже использован')
        return self.issue(client.client_id,obj['subject'],obj['scopes'])

    def issue(self, client, tenant, scopes):
        access, refresh, family = (secrets.token_urlsafe(40) for _ in range(3))
        common = {'client_id':client,'subject':tenant,'scopes':scopes,'resource':self.resource}
        self.store.put('access',access,{**common,'token':access,'expires_at':int(time.time())+3600,
            'family':family},3600)
        self.store.put('refresh',refresh,{**common,'token':refresh,
            'expires_at':int(time.time())+30*86400,'family':family},30*86400)
        return OAuthToken(access_token=access,refresh_token=refresh,token_type='Bearer',
                          expires_in=3600,scope=' '.join(scopes))

    async def load_refresh_token(self, client, refresh_token):
        obj = self.store.get('refresh',refresh_token)
        if not obj or obj['client_id']!=client.client_id or self.store.get('revoked',obj['family']):
            return None
        return RefreshToken.model_validate(obj)

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        obj = self.store.get('refresh',refresh_token.token,consume=True)
        if not obj or obj['client_id']!=client.client_id or not set(scopes).issubset(obj['scopes']):
            raise TokenError('invalid_grant','Недействительный refresh token')
        self.store.put('revoked',obj['family'],True,30*86400)
        return self.issue(client.client_id,obj['subject'],scopes)

    async def load_access_token(self, token):
        obj = self.store.get('access',token)
        if not obj or self.store.get('revoked',obj['family']):
            return None
        return AccessToken.model_validate(obj)

    async def revoke_token(self, token):
        for kind in ('access','refresh'):
            obj = self.store.get(kind,token.token)
            if obj:
                self.store.put('revoked',obj['family'],True,30*86400)
                self.store.delete(kind,token.token)
