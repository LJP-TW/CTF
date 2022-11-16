#!/usr/bin/env python3

import socket

HOST = '127.0.0.1'
PORT = 80

def recvline(conn):
    data = b''
    while True:
        d = conn.recv(1)
        if d != b'\n':
            data += d
        else:
            return data

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)

        data = recvline(conn)
        print('[*] ', data)

        response  = b'HTTP/1.1 200 OK\r\n'
        response += b'Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n'
        response += b'Server: Apache/2.2.14 (Win32)\r\n'
        response += b'Last-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\n'
        response += b'Content-Length: 20\r\n'
        response += b'Content-Type: application/x-www-form-urlencoded\r\n'
        response += b'Connection: Closed\r\n'
        response += b'\r\n'
        response += b'HELLOAAAABBBBCCCCLJP'

        conn.send(response)
