import tornado.ioloop
import tornado.web
from RequestHandler import AuthHandler
from RequestHandler import ProxyHandler
from tornado.options import define, options

define("token", default="http://localhost:8080/oauth/v2/token", help="Endpoint to receive token from")
define("api", default="http://localhost:8080/v2/api/", help="API endpoint")
define("id", default="53b3b1cd5bd2cf3e230041a7_FIXTURE", help="OAuth client id")
define("secret", default="SECURE", help="OAuth client secret")
define("frontend", default="/", help="Path to the frontend")

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
    application.listen(8888)
    tornado.ioloop.IOLoop.instance().start()