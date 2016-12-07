import tornado
from tornado.web import RequestHandler
import hashlib
from itsdangerous import URLSafeTimedSerializer
import json
import logging

class SessionManager(object):

    handler = None

    session = None
    session_raw = None
    session_original = None
    session_secret = None
    session_salt = 'cookie-session'
    SESSION_ID = 'session'

    _cookie_written = False

    def __init__(self, handler):
        self.handler = handler
        self.__init_session()

    def __init_session(self):
        self.session_secret = self.handler.application.settings['cookie_secret']
        self.session_raw = self.handler.get_cookie(self.SESSION_ID, default=None)
        self.session_original = {}
        self.session = {}
        self._load_session()

    def set_cookie(self, **kwargs):
        if self._cookie_written:
            logging.info("Cookie has already been written, ignoring it")
            return
        self._cookie_written = True
        self.handler.set_cookie(**kwargs)

    def finish(self):
        if self.session_changed and self._dump_session():
            self.set_cookie(name=self.SESSION_ID, value=self.session_raw, domain=None, expires=None, path="/", expires_days=None, httponly=True, secure=False)

    @property
    def signing_serializer(self):
        signer_kwargs = dict(
            key_derivation='hmac',
            digest_method=hashlib.sha1
        )
        return URLSafeTimedSerializer(self.session_secret, salt=self.session_salt,
                                      serializer=json,
                                      signer_kwargs=signer_kwargs)

    def resetSession(self):
        self.session_raw = ''
        self.session = {}
        self.session_original = {}
        self.set_cookie(name=self.SESSION_ID, value=self.session_raw, domain=None, expires=1, path="/",
                                expires_days=0, httponly=True, secure=False)

    def _load_session(self):
        if self.session_raw:
            try:
                self.session = self.signing_serializer.loads(self.session_raw, max_age=(2*60*60))
                self.session_original = self.signing_serializer.loads(self.session_raw, max_age=(2*60*60))
            except Exception as e:
                self.resetSession()
                logging.error("Could not load Session %s" % str(e))
                return False
            return True
        return False

    @property
    def session_changed(self):
        x = self.signing_serializer.dump_payload(self.session)
        y = self.signing_serializer.dump_payload(self.session_original)
        if x != y:
            return True
        return False

    def _dump_session(self):
        if self.session:
            try:
                self.session_raw = self.signing_serializer.dumps(self.session)
            except Exception as e:
                self.resetSession()
                logging.error("Could not dump Session %s" % str(e))
                return False
        return True

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

class SessionHandler(RequestHandler):
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