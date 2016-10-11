from tornado.options import options
import urllib
import tornado.httpclient
from tornado.options import options
import logging
from . import Token

class AuthException(Exception):
    code = 500

    def __init__(self, code, message=None):
        self.code = code
        Exception.__init__(self, "HTTP %d: %s" % (self.code, message))

class Auth(object):
    @staticmethod
    def logout(token):
        logging.info("Loggin out user %s" % token.username)
        return True

    @staticmethod
    def auth(username, password):
        url = options.token
        logging.info("Auth Request for user %s" % username)
        logging.debug("Authentication url is %s" % url)
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

        req = tornado.httpclient.HTTPRequest(url, method='POST', body=body, headers=headers, validate_cert=False)
        client = tornado.httpclient.HTTPClient()

        try:
            response = client.fetch(req)
            token = Token(response.body, username, session_duration=options.sessionduration)
            logging.info("Auth Request for user %s was successful" % username)
            return token
        except tornado.httpclient.HTTPError as e:
            if hasattr(e, 'response') and e.response:
                logging.warning("Auth Request for user %s was NOT successful %d" % (username,e.response.code))
                raise AuthException(401, "Auth Request for user %s was NOT successful %d" % (username,e.response.code))
            else:
                logging.warning("Auth Request for user %s was NOT successful %d" % (username, e.code))
                raise AuthException(401, "Auth Request for user %s was NOT successful %d" % (username, e.code))

        logging.error("Auth Request for user %s was NOT possible to perform" % username)
        raise AuthException(401, "Auth Request for user %s was NOT possible to perform" % username)

    @staticmethod
    def refresh(current_token):
        logging.info("Refreshing token for user: %s" % current_token.username)
        url = options.token
        body = urllib.urlencode({
            'client_id': options.id,
            'client_secret': options.secret,
            'grant_type': 'refresh_token',
            'refresh_token': current_token.refresh_token
        })
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        req = tornado.httpclient.HTTPRequest(url, method='POST', body=body, headers=headers, validate_cert=False)
        client = tornado.httpclient.HTTPClient()

        try:
            response = client.fetch(req)
            token = Token(response.body, username=current_token.username, session_duration=options.sessionduration)
            logging.info("Refreshing token for user %s was successful" % token.username)
            return token
        except tornado.httpclient.HTTPError as e:
            if hasattr(e, 'response') and e.response:
                logging.warning("Refreshing token for user %s was NOT successful %d (%s)" % (current_token.username, e.response.code, e.response.body))
                raise AuthException(e.code, "Refreshing token for user %s was NOT successful %d (%s)" % (current_token.username, e.response.code, e.response.body))

        logging.error("Refreshing token for user %s was NOT possible to perform" % current_token.username)
        raise AuthException(500, "Refreshing token for user %s was NOT possible to perform" % current_token.username)