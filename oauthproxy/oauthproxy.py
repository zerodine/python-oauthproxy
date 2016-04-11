import tornado.ioloop
import tornado.web
import tornado.wsgi
from tornado.options import define, options
from requesthandler import AuthHandler, ProxyHandler
import StringIO
import logging, logging.config, yaml
import string
import random

def secret_generator(size=16, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def setup_logger(console_level="DEBUG", file_level="WARNING", file='oauth_proxy.log'):
    logger_config = StringIO.StringIO("""version: 1
formatters:
  console_format:
    format: '%%(asctime)s - %%(name)s - %%(levelname)s - [%%(filename)s:%%(lineno)s:%%(funcName)s()] %%(message)s'
  file_format:
    format: '%%(asctime)s - %%(name)s - %%(levelname)s - [%%(filename)s:%%(lineno)s:%%(funcName)s()] %%(message)s'
handlers:
  console:
    class: logging.StreamHandler
    level: %(console_level)s
    formatter: console_format
    stream: ext://sys.stderr
  file:
    class: logging.FileHandler
    level: %(file_level)s
    formatter: file_format
    filename: %(file)s
loggers:
  console:
    level: %(console_level)s
    handlers: [console]
    propagate: no
  file:
    level: %(file_level)s
    handlers: [file]
    propagate: no
root:
  level: %(console_level)s
  handlers: [console,file]""" % {'console_level':console_level, 'file_level':file_level, 'file':file})
    logging.config.dictConfig(yaml.load(logger_config))


define("token", default="http://localhost:8080/oauth/v2/token", help="Endpoint to receive token from")
define("api", default="http://localhost:8080/v2/api/", help="API endpoint")
define("id", default="53b3b1cd5bd2cf3e230041a7_FIXTURE", help="OAuth client id")
define("secret", default="SECURE", help="OAuth client secret")
define("frontend", default="/", help="Path to the frontend")
define("port", default="8888", help="Port to listen for connections")
define("sessionduration", default=1200, help="Seconds of inactivity before a session gets droped")

secret = secret_generator()

def main(standalone=True,frontend=None,secret=None,id=None,api=None,token=None):
    if standalone:
        tornado.options.parse_command_line()
    else:
        options.frontend = frontend
        options.secret = secret
        options.id = id
        options.api = api
        options.token = token

    settings = {
        'debug': True,
        'cookie_secret': secret
    }

    handlers = [
        (r"/auth", AuthHandler),
        (r"/static/(.*)", tornado.web.StaticFileHandler, {'path': options.frontend, 'default_filename': 'index.html'}),
        (r"/proxy/(.*)", ProxyHandler)
    ]
    setup_logger(console_level='DEBUG')
    logging.info("Application started")

    application = tornado.web.Application(handlers, **settings)
    if standalone:
        application.listen(options.port)
        try:
            tornado.ioloop.IOLoop.instance().start()
        except KeyboardInterrupt:
            pass
    else:
        return tornado.wsgi.WSGIAdapter(application)

if __name__ == "__main__":
    main(standalone=True)
