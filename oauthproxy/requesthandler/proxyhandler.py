import time
import re

import tornado.web
from torndsession.sessionhandler import SessionBaseHandler
from tornado.options import options
from tornado_cors import CorsMixin
import tornado.httpclient
from .libs import Auth, Token
import logging

class ProxyHandler(CorsMixin, SessionBaseHandler):
    CORS_ORIGIN = '*'
    CORS_HEADERS = 'Content-Type'
    CORS_METHODS = 'GET'

    timeout = 5

    prevent_headers = ['Content-Type']
    def _default_request(self):
        self.request_backend(self.session.get('token', default=None))

    @tornado.web.asynchronous
    def get(self, *args, **kwargs):
        self._default_request()

    @tornado.web.asynchronous
    def post(self, *args, **kwargs):
        self._default_request()

    @tornado.web.asynchronous
    def put(self, *args, **kwargs):
        self._default_request()

    @tornado.web.asynchronous
    def delete(self, *args, **kwargs):
        self._default_request()

    @tornado.web.asynchronous
    def options(self, *args, **kwargs):
        self._default_request()

    @tornado.web.asynchronous
    def head(self, *args, **kwargs):
        self._default_request()

    def prepare(self):
        pass

    def _unauthorized(self, token = None):
        if token:
            username = token.username
        else:
            username = "-empty token-"
        self.session.set('token', None)
        logging.warning("Your Session is no longer valid for user %s" % username)
        self.set_status(401)
        self.write({"error": 'Your Session is not valid. Please perform a new login'})
        self.finish()

    def request_backend(self, token):
        url = "%s%s" % (options.api, re.search(r'(?<=proxy/).*', self.request.uri, re.I | re.M).group(0))
        headers = self.request.headers

        unauthenticated = True if self.request.headers.get('X-Unauthenticated') else False
        if unauthenticated:
            token = Token(username='-anonymous-')

        if not token or not isinstance(token, Token):
            return self._unauthorized(token)

        if not token.isCurrent():
            self.refresh_token()

        if not token.validate():
            return self._unauthorized(token)

        token.updateActivity()
        logging.info("Proxy Request for user %s to (%s) %s" % (token.username, self.request.method, url))

        access_token = token.get_access_token()
        if access_token:
            headers['Authorization'] = 'Bearer %s' % access_token

        req = tornado.httpclient.HTTPRequest(url,
                                             method=self.request.method,
                                             body=self.request.body if self.request.body else None,
                                             headers=headers,
                                             follow_redirects=False,
                                             allow_nonstandard_methods=False)
        client = tornado.httpclient.AsyncHTTPClient()

        try:
            client.fetch(req, self.handle_response)
        except tornado.httpclient.HTTPError as e:
            if hasattr(e, 'response') and e.response:
                self.handle_response(e.response)
                logging.debug("Request successful for user %s" % token.username)
            else:
                logging.debug("Request NOT successful for user %s (%s)" % (token.username, str(e)))
                self.set_status(500)
                self.write({"error": 'Internal server error: (%s)' % str(e)})
                self.finish()

    def handle_response(self, response):
        token = self.session.get('token', default=None)
        if response.code == 401:
            if token:
                self.refresh_token()
                self.request_backend(self.session.get('token'))
                return

        self.set_status(response.code)
        for (name, value) in response.headers.get_all():
            if name.lower().startswith('x-') or name.lower() in map(str.lower, self.prevent_headers):
                self.set_header(name, value)

        if token:
            self.set_header('x-session-end', token.session_end)

        self.write(response.body)
        self.finish()

    def refresh_token(self):
        if self.session.get('token_gets_refreshed', default=False):
            timeout = time.time() + self.timeout
            while True:
                if not self.session.get('token_gets_refreshed'):
                    # token refreshed by other call
                    return
                if time.time() > timeout:
                    # got timeout
                    return

        if 'token' in self.session:
            self.session.set('token_gets_refreshed', True)

            token = self.session.get('token')
            code, token = Auth.refresh(token.get_refresh_token())
            if code == 200:
                self.session.set('token_gets_refreshed', False)
                self.session.set('token', Token(token))
                return

        self.session.set('token_gets_refreshed', False)