import tornado.web
from Token import Token
from tornado.options import options
from tornado_cors import CorsMixin
import tornado.httpclient
from Auth import Auth


class ProxyHandler(CorsMixin, tornado.web.RequestHandler):
    CORS_ORIGIN = '*'
    CORS_HEADERS = 'Content-Type'
    CORS_METHODS = 'GET'

    token_refreshed = False

    def prepare(self):
        pass

    def handle_response(self, response):
        if response.code == 401 and not self.token_refreshed:
            self.token_refreshed = True
            token = Token(self.get_secure_cookie('token'))
            code, token = Auth.refresh(token.get_refresh_token())
            if code == 200:
                self.set_secure_cookie('token', token)
                self.request_backend(Token(token))
                return

        self.token_refreshed = False
        self.set_status(response.code)
        for (name, value) in response.headers.get_all():
            self.set_header(name, value)
        self.write(response.body)
        self.finish()

    def request_backend(self, token):
        url = options.api_endpoint + self.request.uri[7:]
        body = self.request.body
        if not body:
            body = None

        access_token = token.get_access_token()
        if not access_token:
            self.set_status(401)
            self.finish()
            return

        headers = self.request.headers
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

    @tornado.web.asynchronous
    def get(self, *args, **kwargs):
        token = Token(self.get_secure_cookie('token'))
        self.request_backend(token)

    @tornado.web.asynchronous
    def post(self):
        return self.get()

    @tornado.web.asynchronous
    def put(self):
        return self.get()