import json
import time


class Token():
    access_token = None
    refresh_token = None
    expires_in = 0
    expires_at = 0
    token_type = None
    scope = None

    def __init__(self, token=None):
        if token:
            token = json.loads(token)
            self.access_token = token['access_token']
            self.refresh_token = token['refresh_token']
            self.expires_in = int(token['expires_in'])
            self.expires_at = int(time.time()) + int(token['expires_in'])
            self.token_type = token['token_type']
            self.scope = token['scope']

    def get_access_token(self):
        return self.access_token

    def get_refresh_token(self):
        return self.refresh_token