import tornado.web
from Auth import Auth
from tornado_cors import CorsMixin


class AuthHandler(CorsMixin, tornado.web.RequestHandler):
    CORS_ORIGIN = '*'
    CORS_HEADERS = 'Content-Type'
    CORS_METHODS = 'POST'

    def post(self):
        username = self.get_argument('username')
        password = self.get_argument('password')

        code, body = Auth.auth(username, password)
        if code == 200:
            self.set_secure_cookie("token", body)
        else:
            self.write(body)

        self.set_status(code)
        self.finish()