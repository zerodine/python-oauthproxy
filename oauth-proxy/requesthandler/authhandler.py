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

    def put(self):
        if self.session.get('token', default=False):
            token = self.session.get('token')
            code, token = Auth.refresh(token.get_refresh_token())

            if code == 200:
                self.session.set('token_gets_refreshed', False)
                self.session.set('token', Token(token))
            else:
                self.write(token)

            self.set_status(code)
            self.finish()

        else:
            self.set_status(403)
            self.write('{error: "no active session"}')
            self.finish()