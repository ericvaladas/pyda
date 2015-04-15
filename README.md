# pyda
A Dark Ages client written in Python

This project is a language rewrite of kojasou's [consoleda](https://github.com/kojasou/consoleda).

### Setup
Clone this repository.
```sh
git clone https://github.com/ericvaladas/pyda.git
```

### Usage
Extend the base Client class and override the packet handlers.
```py
from client import Client as _Client

class Client(_Client):
    def packet_handler_0x0A_system_message(self, packet):
        packet.read_byte()
        message = packet.read_string16()
        print(message)

Client.run('username', 'password')
```
Want to reconnect after being disconnected? No problem.
```py
class Client(_Client):
    def handle_recv(self, recv_buffer):
        super(Client, self).handle_recv(recv_buffer)
        if not recv_buffer:
            self.reconnect()
```

### Todo
- Implement [a better IO Loop](http://tornado.readthedocs.org/en/latest/ioloop.html)
- ~~Generate a working client ID for login~~
- Add more packet handlers
