import os,random,sys,string
from math import cos
from secret import FLAG, SECRET_PASSWORD,HINT
from hashlib import sha256
import socketserver
import signal

USERS = {}
USERS[b'Admin'] = SECRET_PASSWORD
USERS[b'Guest'] = b'No FLAG'

def mao192(s):
	A = 0x41495333
	B = 0x7b754669
	C = 0x6e645468
	D = 0x65456173
	E = 0x74657245
	F = 0x6767217D
	def G(X,Y,Z):
		return (X ^ (~Z | ~Y) ^ Z) & 0xFFFFFFFF
	def H(X,Y,Z):
		return (X ^ Y ^ Z & X) & 0xFFFFFFFF
	def I(X,Y,Z):
		return ((X & ~Z) | (~Z & Y)) & 0xFFFFFFFF
	def J(X,Y,Z):
		return ((X ^ ~Z) | (X & ~Y)) & 0xFFFFFFFF
	def K(X,Y,Z):
		return ((~X & Z) | (~X & Z ^ ~Y)) & 0xFFFFFFFF
	def L(X,Y,Z):
		return ((~X & Y ^ Z) | (X & Y)) & 0xFFFFFFFF
	def M(X,Y):
		return (X << Y | X >> (32 - Y)) & 0xFFFFFFFF
	X = [int((0xFFFFFFFE) * cos(i)) & 0xFFFFFFFF for i in range(256)]
	s_size = len(s)
	s += bytes([0xb0])
	if len(s) % 128 > 120:
		while len(s) % 128 != 0: s += bytes(1)
	while len(s) % 128 < 120: s += bytes(1)
	s += bytes.fromhex(hex(s_size * 8)[2:].rjust(16, '0'))
	for i, b in enumerate(s):
		k, l = int(b), i & 0x1f
		A = (B + M(A + G(B,C,D) + X[k], l)) & 0xFFFFFFFF
		B = (C + M(B + H(C,D,E) + X[k], l)) & 0xFFFFFFFF
		C = (D + M(C + I(D,E,F) + X[k], l)) & 0xFFFFFFFF
		D = (E + M(D + J(E,F,A) + X[k], l)) & 0xFFFFFFFF
		E = (F + M(E + K(F,A,B) + X[k], l)) & 0xFFFFFFFF
		F = (A + M(F + L(A,B,C) + X[k], l)) & 0xFFFFFFFF
	return ''.join(map(lambda x : hex(x)[2:].rjust(8, '0'), [A, F, C, B, D, E]))

def toBytes(s):
	return bytes([ord(c) for c in s])

def vertify(*stuff):
	return mao192(b'&&'.join(stuff)).encode()

class Task(socketserver.BaseRequestHandler):

    def recv(self):
        return self.request.recv(1024).strip()

    def send(self, msg):
        if type(msg) == str :
            msg = bytes([ord(m) for m in msg])
        self.request.sendall(msg)

    def run(self, username, password, session):
        while True :
            self.send('\nWhat do you want to do?\n')
            mac,*sess,cmd = self.recv().split(b'&&')
            if mac == vertify(username,password,*sess,cmd) and session in sess[0]:
                if cmd == b'flag':
                    if username == b'Admin':
                        print("Someone Get Flag!!")
                        self.send(FLAG)
                        return
                    else :
                        self.send('Permission denial\n')
                    break
                elif cmd == b'hint':
                    self.send(HINT)
                elif cmd == b'report':
                    self.send('Leave some message to maojui and kick his ass.\n')
                    print(username.decode() + ':',self.recv().decode())
                elif cmd == b'exit':
                    self.send('exit')
                    break
                else :
                    self.send('Unknown command.')
            else :
                self.send('Refused!\n')
                break
        self.send('See you next time .')

    def handle(self):
        try :
            self.send('Welcome to our system!\nPlease Input your username : ')
            username = self.recv()
            if b'&' in username :
                self.send('')
                raise ValueError
            try :
                password = USERS[username]
            except :
                self.send("Are you new here?\nLet's set a password : ")
                password = self.recv()
                USERS[username] = password
                self.send("Well done.\n\n")
            self.send(f'Hello {username.decode()} \n')
            session = bytes.hex(os.urandom(10)).encode()
            self.send(f'Here is your session ID: {session.decode()}\n')
            self.send(f'and your MAC(username&&password&&sessionID) : {vertify(username,password,session).decode()}\n')
            self.run(username,password,session)
        except:
            self.send("??????")
            self.request.close()


class ForkingServer(socketserver.ForkingTCPServer, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10205
    print(HOST,PORT)
    server = ForkingServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()