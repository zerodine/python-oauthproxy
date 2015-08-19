import tornado.ioloop
import tornado.web
from tornado.options import define, options
from requesthandler import AuthHandler, ProxyHandler

define("token", default="http://localhost:8080/oauth/v2/token", help="Endpoint to receive token from")
define("api", default="http://localhost:8080/v2/api/", help="API endpoint")
define("id", default="53b3b1cd5bd2cf3e230041a7_FIXTURE", help="OAuth client id")
define("secret", default="SECURE", help="OAuth client secret")
define("frontend", default="/", help="Path to the frontend")
define("port", default="8888", help="Port to listen for connections")

if __name__ == "__main__":
    tornado.options.parse_command_line()

    settings = {
        'debug': True,
        'cookie_secret': '][hP+h49UNc46FX3k2v6T;fyY}w$Px?8a(nZ2Z)^wH4wNYFhJX'
    }

    handlers = [
        (r"/auth", AuthHandler),
        (r"/static/(.*)", tornado.web.StaticFileHandler, {'path': options.frontend}),
        (r"/proxy/(.*)", ProxyHandler)
    ]

    application = tornado.web.Application(handlers, **settings)
    application.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()