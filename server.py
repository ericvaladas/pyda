class ServerInfo(object):
    def __init__(self, address, port, name, friendly_name):
        self.address = address
        self.port = port
        self.name = name
        self.friendly_name = friendly_name

    @classmethod
    def from_ip_address(cls, address, port):
        end_point = '{0}:{1}'.format(address, port)

        if end_point == LoginServer.end_point:
            return LoginServer
        elif end_point == TemuairServer.end_point:
            return TemuairServer
        elif end_point == MedeniaServer.end_point:
            return MedeniaServer

    @property
    def end_point(self):
        return '{0}:{1}'.format(self.address, self.port)


LoginServer = ServerInfo('52.88.55.94', 2610, "Login Server", "Login Server")
TemuairServer = ServerInfo('52.88.55.94', 2611, "Temuair Server", "Temuair")
MedeniaServer = ServerInfo('52.88.55.94', 2612, "Medenia Server", "Medenia")
