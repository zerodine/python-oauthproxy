import json
import time
import base64
import hmac
from hashlib import sha1
from tornado.options import options

class Token(object):
    _access_token = None
    refresh_token = None
    expires_in = 0
    expires_at = 0
    token_type = None
    scope = None
    username = None
    latest_activity = None
    session_duration = None # seconds

    def __init__(self, token=None, username=None, session_duration=500):
        if token:
            if not isinstance(token, dict):
                token = json.loads(token)
            self.access_token = token['access_token']
            self.refresh_token = token['refresh_token']
            self.expires_in = int(token['expires_in'])
            self.token_type = token['token_type']
            self.scope = token['scope']
        else:
            self.expires_in = 0

        self.expires_at = int(time.time()) + int(self.expires_in)
        self.username = username
        self.session_duration = session_duration
        self.updateActivity()

    @property
    def access_token(self):
        if not self.validate_token():
            return None
        return self._access_token

    @access_token.setter
    def access_token(self, value):
        self._access_token = value

    def validate_token(self):
        if not options.tokensecret or not options.tokensalt or not options.tokenpayload:
            return True

        access_token = self._access_token
        access_token += b'=' * (-len(access_token) % 4)
        payload, timestamp, signature = map(lambda x: base64.b64decode(x),
                                            base64.urlsafe_b64decode(str(access_token)).split('.'))

        hash = hmac.new(hmac.new(options.tokensecret, options.tokensalt, sha1).digest(),
                        "%s.%s" % (base64.b64encode(payload), base64.b64encode(timestamp)), sha1)
        if hash.digest() == signature and payload == options.tokenpayload:
            return True
        return False

    def get_access_token(self):
        return self.access_token

    def get_refresh_token(self):
        return self.refresh_token

    def updateActivity(self):
        self.latest_activity = int(time.time())

    def isCurrent(self):
        if (int(time.time()) - self.expires_at) >= 0:
            return False
        return True

    def isSessionCurrent(self):
        if (int(time.time()) - (self.latest_activity + self.session_duration)) >= 0:
            return False
        return True

    def validate(self):
        return bool(self.isCurrent() and self.isSessionCurrent())

    @property
    def session_end(self):
        return self.latest_activity + self.session_duration

    def toDictFull(self):
        return {
            'expires_in': self.expires_in,
            'expires_at': self.expires_at,
            'scope': self.scope,
            'latest_activity': self.latest_activity,
            'session_duration': self.session_duration,
            'session_end': self.session_end,
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'token_type': self.token_type,
            'username': self.username
        }

    def toDict(self):
        return {
            'expires_in': self.expires_in,
            'expires_at': self.expires_at,
            'scope': self.scope,
            'latest_activity': self.latest_activity,
            'session_duration': self.session_duration
        }