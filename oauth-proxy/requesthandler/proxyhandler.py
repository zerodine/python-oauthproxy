import time

import tornado.web
from torndsession.sessionhandler import SessionBaseHandler
from tornado.options import options
from tornado_cors import CorsMixin
import tornado.httpclient
from libs import Auth, Token


class ProxyHandler(CorsMixin, SessionBaseHandler):
    CORS_ORIGIN = '*'
    CORS_HEADERS = 'Content-Type'
    CORS_METHODS = 'GET'

    timeout = 5

    prevent_headers = ['Content-Type']

    @tornado.web.asynchronous
    def get(self, *args, **kwargs):
        self.request_backend(self.session.get('token', default=Token()))

    @tornado.web.asynchronous
    def post(self, *args, **kwargs):
        return self.get()

    @tornado.web.asynchronous
    def put(self, *args, **kwargs):
        return self.get()

    @tornado.web.asynchronous
    def delete(self, *args, **kwargs):
        return self.get()

    @tornado.web.asynchronous
    def options(self, *args, **kwargs):
        return self.get()

    @tornado.web.asynchronous
    def head(self, *args, **kwargs):
        return self.get()

    def prepare(self):
        pass

    def request_backend(self, token):
        url = options.api + self.request.uri[7:]
        body = self.request.body
        if not body:
            body = None

        headers = self.request.headers

        access_token = token.get_access_token()
        if access_token:
            headers['Authorization'] = 'Bearer ' + access_token

        req = tornado.httpclient.HTTPRequest(url, method=self.request.method, body=body, headers=headers,
                                             follow_redirects=False, allow_nonstandard_methods=False)
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