#from torndsession.sessionhandler import SessionBaseHandler
from tornado_cors import CorsMixin
from .libs import Auth, AuthException
from session import SessionHandler

class AuthHandler(CorsMixin, SessionHandler):
    CORS_ORIGIN = '*'
    CORS_HEADERS = 'Content-Type'
    CORS_METHODS = 'POST'

    DEFAULT_SESSION_LIFETIME = 1200

    def head(self, *args, **kwargs):
        token = self.session.get('token', default=False)
        if token and token.validate():
            self.set_status(204)
        else:
            self.set_status(401)

    def delete(self, *args, **kwargs):
        Auth.logout(self.session.get('token'))

        self.session.delete('token')
        self.session.delete('token_gets_refreshed')
        self.set_status(204)

    def post(self, *args, **kwargs):
        username = self.get_argument('username')
        password = self.get_argument('password')

        try:
            token = Auth.auth(username, password)
            self.session.set('token', token)
            self.write(token.toDict())
            self.set_status(200)
        except AuthException as e:
            self.write({"error": str(e)})
            self.set_status(e.code)

    def put(self, *args, **kwargs):
        if self.session.get('token', default=False):
            current_token = self.session.get('token')

            try:
                token = Auth.refresh(current_token)
                self.session.set('token_gets_refreshed', False)
                self.session.set('token', token)
                self.set_header('x-session-end', token.session_end)
                self.write(token.toDict())
                self.set_status(200)
                del current_token
            except AuthException as e:
                self.write({"error": str(e)})
                self.set_status(e.code)
        else:
            self.set_status(403)
            self.write({"error": "no active session"})
