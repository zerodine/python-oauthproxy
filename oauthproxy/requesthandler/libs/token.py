import json
import time


class Token(object):
    access_token = None
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

    def get_access_token(self):
        return self.access_token

    def get_refresh_token(self):
        return self.refresh_token

    def updateActivity(self):
        self.latest_activity = int(time.time())

    def isCurrent(self):
        if not self.access_token:
            return True
        if (int(time.time()) - self.expires_at) >= 0:
            return False
        return True

    def isSessionCurrent(self):
        if not self.access_token:
            return True
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