"""Persistent tenant boundary. Secrets are encrypted; opaque grants hashed."""
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from cryptography.fernet import Fernet


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = self.directory / 'vault.key'
        if not key.exists():
            fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(Fernet.generate_key())
        self.cipher = Fernet(key.read_bytes())
        self.path = self.directory / 'service.sqlite'
        with self.db() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS objects(kind TEXT, key TEXT, data TEXT, expires REAL,
              PRIMARY KEY(kind,key));
            CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, password TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS communities(tenant TEXT, alias TEXT, group_id INTEGER,
              credentials TEXT, PRIMARY KEY(tenant,alias));
            CREATE TABLE IF NOT EXISTS writes(tenant TEXT, operation TEXT, status TEXT,
              result TEXT, PRIMARY KEY(tenant,operation));
            ''')
        os.chmod(self.path, 0o600)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def put(self, kind, key, data, ttl=3600):
        # Encrypt object payloads too: OAuth client secrets/codes never plaintext on disk.
        enc = self.cipher.encrypt(json.dumps(data).encode()).decode()
        with self.db() as db:
            db.execute('DELETE FROM objects WHERE expires < ?', (time.time(),))
            db.execute('INSERT OR REPLACE INTO objects VALUES(?,?,?,?)',
                       (kind, digest(key), enc, time.time()+ttl))

    def get(self, kind, key, consume=False):
        with self.db() as db:
            if consume:
                db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT data,expires FROM objects WHERE kind=? AND key=?',
                             (kind,digest(key))).fetchone()
            if row is None or row['expires'] < time.time():
                return None
            if consume:
                db.execute('DELETE FROM objects WHERE kind=? AND key=?', (kind,digest(key)))
            return json.loads(self.cipher.decrypt(row['data'].encode()))

    def delete(self, kind, key):
        with self.db() as db:
            db.execute('DELETE FROM objects WHERE kind=? AND key=?', (kind,digest(key)))

    def user(self, name, password):
        if not name or len(name)>80 or len(password)<16:
            raise ValueError('Нужно имя и пароль длиной от 16 символов')
        salt = secrets.token_bytes(16)
        value = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
        encoded = salt.hex()+':'+value.hex()
        with self.db() as db:
            db.execute('INSERT OR REPLACE INTO users VALUES(?,?)', (name,encoded))
            # Rotation invalidates all existing grants (small private service).
            db.execute("DELETE FROM objects WHERE kind IN ('access','refresh','code','pending')")

    def verify(self, name, password):
        with self.db() as db:
            row = db.execute('SELECT password FROM users WHERE name=?',(name,)).fetchone()
        encoded = row['password'] if row else '00'*16+':'+'00'*64
        salt, expected = encoded.split(':')
        value = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384,r=8,p=1)
        return bool(row) and hmac.compare_digest(value.hex(), expected)

    def community(self, tenant, alias, group_id, credentials):
        if int(group_id)<=0 or not alias or not credentials.get('token'):
            raise ValueError('Нужны alias, положительный group_id и токен')
        with self.db() as db:
            if not db.execute('SELECT 1 FROM users WHERE name=?',(tenant,)).fetchone():
                raise ValueError('Пользователь не создан')
            enc = self.cipher.encrypt(json.dumps(credentials).encode()).decode()
            db.execute('INSERT OR REPLACE INTO communities VALUES(?,?,?,?)',
                       (tenant,alias,int(group_id),enc))

    def communities(self, tenant):
        with self.db() as db:
            return [dict(row) for row in db.execute(
                'SELECT alias,group_id FROM communities WHERE tenant=? ORDER BY alias',(tenant,))]

    def credentials(self, tenant, alias):
        with self.db() as db:
            row = db.execute('SELECT group_id,credentials FROM communities WHERE tenant=? AND alias=?',
                             (tenant,alias)).fetchone()
        if row is None:
            raise ValueError('Сообщество не подключено к вашей учётной записи')
        return row['group_id'], json.loads(self.cipher.decrypt(row['credentials'].encode()))
