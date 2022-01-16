#!/usr/bin/env python3

import socket

HOST = '0.0.0.0'
PORT = 7414

def recvline(conn):
    data = b''
    while True:
        d = conn.recv(1)
        if d != b'\n':
            data += d
        else:
            return data

def handle(conn, data):
    if b'/antibalsn/regist' in data:
        for i in range(5):
            data = recvline(conn)        
            print(data)
        payload  = 'HTTP/1.0 200 OK\r\n'
        payload += 'Server: BaseHTTP/0.6 Python/3.8.12\r\n'
        payload += 'Content-type: text/html\r\n'
        payload += '\r\n'
        payload += '05INporeqfZjZ7lgrUtfi/dnmpswNW127z+KKN8h8RE=\n'
        payload += 'OZIKeiOhKij5kxxSvZNQ+29XPzP5Q61kNGFyb+bMn8A=\n'
        payload += 'AGHrWuOtb5rQ+OC7CbmDPQ=='
        payload = payload.encode()
        conn.send(payload)

    elif b'/antibalsn/gameOver/' in data:
        for i in range(5):
            data = recvline(conn)        
            print(data)
        payload  = 'HTTP/1.0 200 OK\r\n'
        payload += 'Server: BaseHTTP/0.6 Python/3.8.12\r\n'
        payload += 'Content-type: text/html\r\n'
        payload += '\r\n'
        payload = payload.encode()
        conn.send(payload)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    
    while True:
        try:
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                data = recvline(conn)        
                print(data)
                handle(conn, data)
        except KeyboardInterrupt:
            break
        