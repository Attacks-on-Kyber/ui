import socket
import json,hashlib
import re

server = json.load(open('./client_config.json'))
client = socket.socket()
client.connect((server['server_IP'], server['server_port_1']))

def passwd_md5(b):
    m = hashlib.md5()
    m.update(b.encode())
    return m.hexdigest().upper()

def recved_main(data_len):
    '''接收报文正文'''
    size = 0
    tmp = b''
    while size < data_len:
        data = client.recv(data_len - size)
        if not data:
            break
        tmp += data
        size += len(data)
    tmp = tmp.decode()
    return tmp

def login(arg):
    '''
    客户端登录请求
    '''
    login_package = dict()
    login_package['login'] = 1
    login_package['args'] = arg
    login_package = json.dumps(login_package)
    login_package = login_package.encode()
    login_package_len = '{:<15}'.format(len(login_package))   #报头长度，左对齐15位
    client.send(login_package_len.encode())
    client.send(login_package)
    
    ret_len = client.recv(15).decode()
    ret_len = int(ret_len.strip())#接收报文长度
    ret = recved_main(ret_len)   
    ret = json.loads(ret)
    back = ret["return"]
    print(ret)
    return back

def register(arg):
    '''
    客户端注册账号请求
    '''
    register_package = dict()
    register_package["login"] = 2
    register_package["args"] = arg
    register_package = json.dumps(register_package, ensure_ascii=False)
    register_package = register_package.encode()
    register_package_len = '{:<15}'.format(len(register_package))  # 报头长度
    client.send(register_package_len.encode())  # 发送报头长度
    client.send(register_package)  # 发送报文
    ret_len = client.recv(15).decode()  # 接收响应长度
    ret_len = int(ret_len.strip())

    ret = recved_main(ret_len)  # 接收报文长度
    ret = json.loads(ret)

    back = ret["return"]

    return back

def modify_password(arg):
    modify_password_package = dict()
    modify_password_package["login"] = 3
    modify_password_package["args"] = arg
    modify_password_package = json.dumps(modify_password_package)
    modify_password_package = modify_password_package.encode()
    modify_password_package_len = '{:<15}'.format(len(modify_password_package))  # 报头长度
    client.send(modify_password_package_len.encode())  # 发送报头长度
    client.send(modify_password_package)  # 发送报文
    ret_len = client.recv(15).decode()  # 接收响应长度
    ret_len = int(ret_len.strip())

    ret = recved_main(ret_len)  # 接收报文长度
    ret = json.loads(ret)
    back = ret["return"]

    return back

def forget_password(arg):
    forget_password_package = dict()
    forget_password_package["login"] = 4
    forget_password_package["args"] = arg
    forget_password_package = json.dumps(forget_password_package)
    forget_password_package = forget_password_package.encode()
    forget_password_package_len = '{:<15}'.format(len(forget_password_package))  # 报头长度
    client.send(forget_password_package_len.encode())  # 发送报头长度
    client.send(forget_password_package)  # 发送报文
    ret_len = client.recv(15).decode()  # 接收响应长度
    ret_len = int(ret_len.strip())

    ret = recved_main(ret_len)  # 接收报文长度

    ret = json.loads(ret)
    back = ret["return"]

    return back

def exit():
    exit_package = dict()
    exit_package["login"] = 0
    exit_package["args"] = 'exit'
    exit_package = json.dumps(exit_package)
    exit_package = exit_package.encode()
    exit_package_len = '{:<15}'.format(len(exit_package))  # 报头长度
    client.send(exit_package_len.encode())  # 发送报头长度
    client.send(exit_package)  # 发送报文
    client.close()

