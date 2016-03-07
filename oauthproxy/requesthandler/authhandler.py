from torndsession.sessionhandler import SessionBaseHandler
from tornado_cors import CorsMixin
from .libs import Auth


class AuthHandler(CorsMixin, SessionBaseHandler):
    CORS_ORIGIN = '*'
    CORS_HEADERS = 'Content-Type'
    CORS_METHODS = 'POST'

    def delete(self, *args, **kwargs):
        pass

    def post(self, *args, **kwargs):
        username = self.get_argument('username')
        password = self.get_argument('password')

        token = Auth.auth(username, password)
        if token:
            self.session.set('token', token)
        else:
            self.write(token.toDict())

        self.set_status(200)
        self.finish()

    def put(self, *args, **kwargs):
        if self.session.get('token', default=False):
            current_token = self.session.get('token')
            token = Auth.refresh(current_token)

            if token:
                self.session.set('token_gets_refreshed', False)
                self.session.set('token', token)
            else:
                self.write(token.toDict())
            del current_token

            self.set_status(200)
            self.finish()

        else:
            self.set_status(403)
            self.write('{error: "no active session"}')
            self.finish()