from torndsession.sessionhandler import SessionBaseHandler
from tornado_cors import CorsMixin
from libs import Auth, Token


class AuthHandler(CorsMixin, SessionBaseHandler):
    CORS_ORIGIN = '*'
    CORS_HEADERS = 'Content-Type'
    CORS_METHODS = 'POST'

    def post(self):
        username = self.get_argument('username')
        password = self.get_argument('password')

        code, body = Auth.auth(username, password)
        if code == 200:
            self.session['token'] = Token(body)
            print "received new token"
        else:
            self.write(body)

        self.set_status(code)
        self.finish()