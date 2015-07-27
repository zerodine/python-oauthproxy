import json


class Token():
    token = {}

    def __init__(self, token):
        if token:
            self.token = json.loads(token)

    def get_access_token(self):
        if "access_token" in self.token:
            return self.token["access_token"]

        return None

    def get_refresh_token(self):
        if "refresh_token" in self.token:
            return self.token["refresh_token"]

        return None