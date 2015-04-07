# pyda
A Dark Ages client written in Python

This project is a rewrite of [kojasou's consoleda](https://github.com/kojasou/consoleda) which was written in C#.

### Setup
Clone this repository.
```sh
git clone https://github.com/ericvaladas/pyda.git
```
  
Install dependencies.
```sh
pip install -r requirements.txt
```

### Usage
Extend the base Client class and override or create some packet handlers.
```py
from client import Client as _Client

class Client(_Client):
    def packet_handler_0x0A_system_message(self, packet):
            packet.read_byte()
            message = packet.read_string16()
            print(message)

Client.run('username', 'password')
```
