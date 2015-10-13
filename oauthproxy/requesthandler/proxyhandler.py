import time
import re

import tornado.web
from torndsession.sessionhandler import SessionBaseHandler
from tornado.options import options
from tornado_cors import CorsMixin
import tornado.httpclient
from .libs import Auth, Token


class ProxyHandler(CorsMixin, SessionBaseHandler):
    CORS_ORIGIN = '*'
    CORS_HEADERS = 'Content-Type'
    CORS_METHODS = 'GET'

    timeout = 5

    prevent_headers = ['Content-Type']
    def _default_request(self):
        self.request_backend(self.session.get('token', default=Token()))

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

    def request_backend(self, token):
        url = "%s%s" % (options.api, re.search(r'(?<=proxy/).*', self.request.uri, re.I | re.M).group(0))

        headers = self.request.headers

        access_token = token.get_access_token()
        if access_token:
            headers['Authorization'] = 'Bearer ' + access_token

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
            else:
                self.set_status(500)
                self.write('Internal server error:\n' + str(e))
                self.finish()

    def handle_response(self, response):
        if response.code == 401:
            if self.session.get('token', default=False):
                self.refresh_token()
                self.request_backend(self.session.get('token'))
                return

        self.set_status(response.code)
        for (name, value) in response.headers.get_all():
            if name.lower().startswith('x-') or name.lower() in map(str.lower, self.prevent_headers):
                self.set_header(name, value)
        self.write(response.body)
        self.finish()

    def refresh_token(self):
        if self.session.get('token_gets_refreshed', default=False):
            print "token gets refreshed by other call"
            timeout = time.time() + self.timeout
            while True:
                if not self.session.get('token_gets_refreshed'):
                    print "token refreshed by other call"
                    return
                if time.time() > timeout:
                    print "got timeout"
                    return

        if 'token' in self.session:
            self.session.set('token_gets_refreshed', True)

            token = self.session.get('token')
            code, token = Auth.refresh(token.get_refresh_token())
            if code == 200:
                print "token refreshed"
                self.session.set('token_gets_refreshed', False)
                self.session.set('token', Token(token))
                return

        self.session.set('token_gets_refreshed', False)