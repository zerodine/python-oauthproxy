import tornado
import hashlib
from itsdangerous import URLSafeTimedSerializer
import json

class SessionManager(object):

    handler = None

    session = {}
    session_raw = None
    session_secret = None
    session_salt = 'cookie-session'
    SESSION_ID = 'session'


    def __init__(self, handler):
        self.handler = handler
        self.__init_session()

    def __init_session(self):
        self.session_secret = self.handler.application.settings['cookie_secret']
        self.session_raw = self.handler.get_cookie(self.SESSION_ID, default=None)
        self._load_session()

    def finish(self):
        if self._dump_session():
            self.handler.set_cookie(name=self.SESSION_ID, value=self.session_raw, domain=None, expires=None, path="/", expires_days=None)

    @property
    def signing_serializer(self):
        signer_kwargs = dict(
            key_derivation='hmac',
            digest_method=hashlib.sha1
        )
        return URLSafeTimedSerializer(self.session_secret, salt=self.session_salt,
                                      serializer=json,
                                      signer_kwargs=signer_kwargs)


    def _load_session(self):
        if self.session_raw:
            self.session = self.signing_serializer.loads(self.session_raw, max_age=(2*60*60))
            return True
        return False

    def _dump_session(self):
        if self.session:
            self.session_raw = self.signing_serializer.dumps(self.session)
            return True
        return False

    def get(self, key, default=None):
        """
        Return session value with name as key.
        """
        return self.session.get(key, default)

    def set(self, key, value):
        """
        Add/Update session value
        """
        self.session[key] = value

    def delete(self, key):
        """
        Delete session key-value pair
        """
        if key in self.session:
            del self.session[key]
    __delitem__ = delete

    def iterkeys(self):
        return iter(self.session)

    __iter__ = iterkeys

    def keys(self):
        """
        Return all keys in session object
        """
        return self.session.keys()

    def __setitem__(self, key, value):
        self.set(key, value)

    def __getitem__(self, key):
        val = self.get(key)
        if val: return val
        raise KeyError('%s not found' % key)

    def __contains__(self, key):
        return key in self.session

class SessionHandler(tornado.web.RequestHandler):
    @property
    def session(self):
        return self._create_mixin(self, '__session_manager', SessionManager)

    def _create_mixin(self, context, inner_property_name, session_handler):
        if not hasattr(context, inner_property_name):
            setattr(context, inner_property_name, session_handler(context))
        return getattr(context, inner_property_name)

    def finish(self, chunk=None):
        self.session.finish()
        super(SessionHandler, self).finish(chunk)