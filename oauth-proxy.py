import tornado.ioloop
import tornado.web
from RequestHandler import AuthHandler
from RequestHandler import ProxyHandler
from tornado.options import define


define("token_endpoint", default="http://localhost:8080/oauth/v2/token", help="Endpoint to receive token from")
define("api_endpoint", default="http://localhost:8080/v2/api/", help="API endpoint")
define("client_id", default="53b3b1cd5bd2cf3e230041a7_FIXTURE", help="OAuth client id")
define("client_secret", default="SECURE", help="OAuth client secret")

if __name__ == "__main__":
    settings = {
        'debug': True,
        'cookie_secret': '][hP+h49UNc46FX3k2v6T;fyY}w$Px?8a(nZ2Z)^wH4wNYFhJX'
    }

    handlers = [
        (r"/auth", AuthHandler),
        (r"/static/(.*)", tornado.web.StaticFileHandler, {'path': '/Users/philipp/Workspace/cyberlink/oss2/frontend'}),
        (r"/proxy/(.*)", ProxyHandler)
    ]

    application = tornado.web.Application(handlers, **settings)
    application.listen(8888)
    tornado.ioloop.IOLoop.instance().start()