import time
import re
import requests
import tornado.web
from session import SessionHandler
from tornado.options import options
import tornado.httpclient
from .libs import Auth, Token
import logging
from urlparse import urlparse

class ProxyHandler(SessionHandler):
    CORS_ORIGIN = None
    CORS_HEADERS = 'Content-Type'
    CORS_METHODS = 'GET'
    CORS_CREDENTIALS = True
    CORS_MAX_AGE = 86400
    CORS_EXPOSE_HEADERS = None

    timeout = 5

    public_routes = []

    def initialize(self, **kwargs):
        if 'public' in kwargs:
            self.public_routes = kwargs['public']

    prevent_headers = ['Access-Control-Allow-Origin', 'Set-Cookie', 'Server', 'Etag', 'Date']

    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", self.CORS_ORIGIN if self.CORS_ORIGIN else options.corsorigin )

        if self.CORS_EXPOSE_HEADERS:
            self.set_header('Access-Control-Expose-Headers', self.CORS_EXPOSE_HEADERS)

    @property
    def token(self):
        token = self.session.get('token', default=None)
        if isinstance(token, dict):
            username = self.session.get('username', default=None)
            session_duration = token.get('session_duration', options.sessionduration)
            token = Token(token=token, username=username, session_duration=session_duration)
        return token

    def _default_request(self):
        self.request_backend(self.token)

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

    def _unauthorized(self, token=None, url=None):
        if token and isinstance(token, (Token)):
            username = token.username
        else:
            username = "-empty/unkown token-"
        #
        logging.warning("Your Session is no longer valid for user %s (%s)" % (username, url))

        referer = options.referer
        if not referer:
            self.session.set('token', None)
            self.set_status(401)
            self.write({"error": 'Your Session is not valid. Please perform a new login'})
            self.finish()
        else:
            self.redirect(referer % (self.request.protocol + "://" + self.request.host + self.request.uri), permanent=False) #'http://nextgen.bexio.dev/login?_referer=%s' % (self.request.protocol + "://" + self.request.host + self.request.uri), permanent=False)

    def _isPublicRequest(self):
        if not self.public_routes: return False
        for pr in self.public_routes:
            if re.match(pr, self.request.uri, re.I | re.S):
                return True

    def request_backend(self, token):
        url = "%s%s" % (options.api, re.search(r'(?<=proxy/).*', self.request.uri, re.I | re.M).group(0))
        headers = self.request.headers
        headers['Host'] = urlparse(url=url).hostname

        unauthenticated = True if self.request.headers.get('X-Unauthenticated') else False
        if unauthenticated or self._isPublicRequest():
            token = Token(username='-anonymous-')

        if not token or not isinstance(token, Token):
            return self._unauthorized(token, url)

        if token.get_access_token() and not token.isCurrent():
            self.refresh_token()

        if token.get_access_token() and not token.validate():
            return self._unauthorized(token, url)

        token.updateActivity()
        logging.debug("Proxy Request for user %s to (%s) %s" % (token.username, self.request.method, url))

        access_token = token.get_access_token()
        if access_token:
            headers['Authorization'] = 'Bearer %s' % access_token

        response = requests.request(self.request.method, url,
                                    headers=headers,
                                    data=self.request.body if self.request.body else None,
                                    verify=False)
        logging.info("Proxy Response for user %s to (%s) %s - %s" % (token.username, self.request.method, url, response.status_code))
        self.handle_response(response)

    def set_cors_headers(self):
        if self.CORS_HEADERS:
            self.set_header('Access-Control-Allow-Headers', self.CORS_HEADERS)
        if self.CORS_METHODS:
            self.set_header('Access-Control-Allow-Methods', self.CORS_METHODS)
        else:
            self.set_header('Access-Control-Allow-Methods', self._get_methods())
        if self.CORS_CREDENTIALS != None:
            self.set_header('Access-Control-Allow-Credentials',
                "true" if self.CORS_CREDENTIALS else "false")
        if self.CORS_MAX_AGE:
            self.set_header('Access-Control-Max-Age', self.CORS_MAX_AGE)

        if self.CORS_EXPOSE_HEADERS:
            self.set_header('Access-Control-Expose-Headers', self.CORS_EXPOSE_HEADERS)

    def handle_response(self, response):
        if response.status_code == 401:
            if self.token:
                if self.refresh_token():
                    self.request_backend(self.token)
                    return

        self.set_status(response.status_code)
        for (name, value) in response.headers.iteritems():
            if name.lower().startswith('x-') or name.lower().startswith('content-') or name.lower() in map(str.lower, self.prevent_headers):
                self.set_header(name, value)

        self.set_cors_headers()

        if self.token:
            self.set_header('x-session-end', self.token.session_end)

        if response.status_code != 204:
            self.write(response.content)
        self.finish()

    def refresh_token(self):
        #if self.session.get('token_gets_refreshed', default=False):
        #    time.sleep(self.timeout)
        #    return False

        if 'token' in self.session:
            #self.session.set('token_gets_refreshed', True)
            token = Auth.refresh(self.token)
            if token:
                self.session.set('token', token)
                #self.session.set('token_gets_refreshed', False)
                return True

        #self.session.set('token_gets_refreshed', False)
        return False