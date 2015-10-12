from tornado.options import options
import urllib
import tornado.httpclient


class Auth(object):
    @staticmethod
    def auth(username, password):
        url = options.token
        body = urllib.urlencode({
            'client_id': options.id,
            'client_secret': options.secret,
            'grant_type': 'password',
            'username': username,
            'password': password
        })
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        req = tornado.httpclient.HTTPRequest(url, method='POST', body=body, headers=headers)
        client = tornado.httpclient.HTTPClient()

        try:
            response = client.fetch(req)
            return 200, response.body
        except tornado.httpclient.HTTPError as e:
            if hasattr(e, 'response') and e.response:
                return e.response.code, e.response.body

        return 500, "internal server error"

    @staticmethod
    def refresh(refresh_token):

        url = options.token
        body = urllib.urlencode({
            'client_id': options.id,
            'client_secret': options.secret,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        })
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        req = tornado.httpclient.HTTPRequest(url, method='POST', body=body, headers=headers)
        client = tornado.httpclient.HTTPClient()

        try:
            response = client.fetch(req)
            return 200, response.body
        except tornado.httpclient.HTTPError as e:
            if hasattr(e, 'response') and e.response:
                return e.response.code, e.response.body

        return 500, "internal server error"