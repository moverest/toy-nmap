from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

authorizer = DummyAuthorizer()
authorizer.add_anonymous("./ftp")

handler = FTPHandler
handler.authorizer = authorizer
handler.permit_foreign_addresses = True

server = FTPServer(("127.0.0.1", 2121), handler)
server.serve_forever()
