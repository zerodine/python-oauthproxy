#from torndsession.sessionhandler import SessionBaseHandler
from tornado_cors import CorsMixin
from .libs import Auth, AuthException, Token
from session import SessionHandler
import logging


class AuthHandler(CorsMixin, SessionHandler):
    CORS_ORIGIN = '*'
    CORS_HEADERS = 'Content-Type'
    CORS_METHODS = 'POST'

    DEFAULT_SESSION_LIFETIME = 1200

    def head(self, *args, **kwargs):
        token = False
        token_raw = self.session.get('token', default=False)
        if token_raw:
            try:
                token = Token(token=token_raw)
            except Exception as e:
                logging.debug("Could not Load Token from Session - %s" % (str(e)))

        logging.info("Proxy Request for user %s to (%s) %s" % (token.username if token else '-anyonymous-', self.request.method, self.request.uri))


        if token and token.validate():
            self.set_status(204)
        else:
            self.write({"error": "Could not load Token from Session"})
            self.set_status(401)

    def delete(self, *args, **kwargs):
        Auth.logout(Token(token=self.session.get('token', None)))
        self.session.resetSession()
        self.set_status(204)

    def post(self, *args, **kwargs):
        username = self.get_argument('username')
        password = self.get_argument('password')

        try:
            token = Auth.auth(username, password)
            self.session.set('token', token.toDictFull())
            self.session.set('username', username)
            self.write(token.toDict())
            self.set_status(200)
        except AuthException as e:
            self.write({"error": str(e)})
            logging.debug("Could not Authenticate" % (str(e)))
            self.set_status(e.code)
        self.finish()

    def put(self, *args, **kwargs):
        if self.session.get('token', default=False):
            current_token = self.session.get('token')

            try:
                token = Auth.refresh(Token(token=current_token, username=self.session.get('username', default=None)))
                self.session.set('token_gets_refreshed', False)
                self.session.set('token', token.toDictFull())
                self.session.set('username', token.username)
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
