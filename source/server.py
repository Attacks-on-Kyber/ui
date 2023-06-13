import socket
import json
import threading
import hashlib
import os
import server_db 

log_reg_socket = socket.socket() #用于响应登录注册等功能
log_reg_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
log_reg_socket.bind(("127.0.0.1", 50280))
log_reg_socket.listen(5)

data_socket = socket.socket()
data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
data_socket.bind(("127.0.0.1", 50281))
data_socket.listen(5)

file_socket = socket.socket()  # 创建一个套接字，传文件
file_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
file_socket.bind(("127.0.0.1", 50282))
file_socket.listen(5)

Online_list = []
File_list = []

def recved_main(data_len, sock):
    '''接收报文正文'''
    size = 0
    tmp = b''
    while size < data_len:
        data = sock.recv(data_len - size)
        if not data:
            break
        tmp += data
        size += len(data)
    tmp = tmp.decode()
    return tmp

def login_register(conn):
    '''登录和注册请求响应'''
    try:
        while True:
            client_request_len = conn.recv(15).decode()    #接收报文长度
            if len(client_request_len) == 0:
                break
            client_request_len = int(client_request_len.strip())

            client_request = recved_main(client_request_len, conn)   #接收报文

            client_request = json.loads(client_request)         #解析报文成字典格式
            if client_request["login"] == 0:
                break
            elif client_request["login"] == 1:         #登录请求
                r = login(client_request)
                if r["return"] != 0:            #返回值不为0，登录失败
                    reg = json.dumps(r)
                    reg = reg.encode()
                    reg_len = '{:<15}'.format(len(reg))
                    conn.send(reg_len.encode())
                    conn.send(reg)
                else:
                    reg = json.dumps(r)
                    reg = reg.encode()#登录成功
                    reg_len = '{:<15}'.format(len(reg))
                    conn.send(reg_len.encode())
                    conn.send(reg)
                    codd, addr = data_socket.accept()    #连接第二个端口，收发消息
                    print(addr, "端口2已连接")
                    email = client_request["args"]["Email"]
                    user_name = server_db.email2name(email)
                    threading.Thread(target=home_page, args=(codd, email)).start()   #开启线程接消息

                    conn_3, addr_3 = file_socket.accept()
                    File_list.append([conn_3,email])
                    print(addr_3, '端口3已连接')
                    threading.Thread(target=recv_files, args=(conn_3, email)).start()


            elif client_request["login"] == 2:
                r = register(client_request)

                reg = json.dumps(r)
                reg = reg.encode()
                reg_len = '{:<15}'.format(len(reg))
                conn.send(reg_len.encode())
                conn.send(reg)

            elif client_request["login"] == 3:
                r = modify_password(client_request)

                reg = json.dumps(r)
                reg = reg.encode()
                reg_len = '{:<15}'.format(len(reg))
                conn.send(reg_len.encode())
                conn.send(reg)

            elif client_request["login"] == 4:
                r = forget_pd(client_request)

                reg = json.dumps(r)
                reg = reg.encode()
                reg_len = '{:<15}'.format(len(reg))
                conn.send(reg_len.encode())
                conn.send(reg)

    except Exception as e:
        print(e)

    finally:
        conn.close()
        print('端口1连接关闭')


def login(client_login_request):
    '''
    登录 
    输入请求的参数字典
    输出响应返回的参数字典
    '''
    server_login_response = dict()
    server_login_response["login"] = 1
    email = client_login_request['args']['Email']
    password = client_login_request['args']['password']
    
    check_email = server_db.check_Email(email)
    if check_email == 1: #邮箱不存在
        server_login_response["return"] = 2
        return server_login_response    
    check_password = server_db.check_password(email, password)
    if check_password == 1: #密码不存在
        server_login_response["return"] = 1
        return server_login_response
    
    email_list = []
    for item in Online_list:
        email_ = item[1]
        email_list.append(email_)   
    if email in email_list:
        server_login_response["return"] = 3
        return server_login_response
    
    server_login_response["return"] = 0
    return server_login_response

def register(client_register_request):
    '''
    注册
    输入请求的参数字典
    输出响应返回的参数字典
    '''
    server_register_response = dict()
    server_register_response["login"] = 2
    email = client_register_request["args"]["Email"]
    user_name = client_register_request["args"]["user_name"]
    password = client_register_request["args"]["password"]
    
    check_email = server_db.check_Email(email)        # 验证邮箱是否重复
    if check_email == 0: #邮箱存在
        server_register_response["return"] = 1                #用户名已存在
        return server_register_response
    
    server_db.add_user(email, user_name, password)
    server_register_response["return"] = 0 
    return server_register_response

def modify_password(client_modify_password_request):
    '''
    修改密码
    输入请求的参数字典
    输出响应返回的参数字典
    '''
    server_modify_password_response = dict()
    server_modify_password_response["login"] = 3
    email = client_modify_password_request['args']['Email']          #查询数据库
    old_passwd = client_modify_password_request['args']['old_password']
    new_passwd = client_modify_password_request['args']['new_password']
    check_email = server_db.check_Email(email)        # 验证邮箱是否重复
    if check_email == 1: #邮箱不存在
        server_modify_password_response["return"] = 1
        return server_modify_password_response
    check_password = server_db.check_password(email, old_passwd)
    if check_password == 1: #密码错误
        server_modify_password_response["return"] = 2
        return server_modify_password_response

    server_db.modify_pd(email, new_passwd)
    server_modify_password_response["return"] = 0
    return server_modify_password_response

def forget_pd(client_forget_pd_request):
    '''
    重置密码
    输入请求的参数字典
    输出响应返回的参数字典
    '''
    server_forget_pd_response = dict()
    server_forget_pd_response["login"] = 4
    email = client_forget_pd_request['args']['Email']          #查询数据库
    new_passwd = client_forget_pd_request['args']['new_password']
    # 修改密码
    check_email = server_db.check_Email(email)  
    if  check_email == 1:
        server_forget_pd_response["return"] = 1
        return server_forget_pd_response

    server_db.modify_pd(email, new_passwd)
    server_forget_pd_response["return"] = 0
    return server_forget_pd_response

def home_page(data_sock, email):
    '''打开个人主页'''
    email_list = []
    for item in Online_list:
        email_ = item[1]
        email_list.append(email_)
    if  email not in email_list:
        Online_list.append([data_sock, email])
        
    broadcast_online()
        
    try:
        while True:
            action_len = data_sock.recv(15).decode()
            if not action_len:
                continue
            action_len = int(action_len.strip())
            action = recved_main(action_len, data_sock)
            if 'login' in action:
                if 'args' in action:
                    Online_list.remove([data_sock, email])
                    broadcast_online()
                    down = dict()                         #提示某人下线
                    down['down_line'] = email
                    down = json.dumps(down, ensure_ascii=False)
                    down = down.encode()
                    down_len = '{:<15}'.format(len(down))
                    for list in Online_list:
                        send_conn = list[0]
                        if send_conn is not data_sock:
                            try:
                                send_conn.send(down_len.encode())         # 发送下线消息
                                send_conn.send(down)
                            except:
                                pass

                    data_sock.close()
                    # print(address)
                    print('端口2连接关闭')
                else:
                    continue
            elif 'personal_talk' in action:
                action = json.loads(action)
                recv_email = action['personal_talk']
                message = action['message']
                if recv_email != email:
                    threading.Thread(target=personal_talk, args=(recv_email, email, message)).start()  # 接收邀请聊天消息并转发
            elif 'group' in action:
                action = json.loads(action)
                send_email = action['group']
                msg = action['message']
                if len(msg) != 0:
                    threading.Thread(target=group_talk, args=(send_email, msg)).start()  # 接收邀请聊天消息并转发
    except Exception as e:
        print(e)
               
def broadcast_online():
    '''广播在线信息'''
    online_package = dict()
    online_email = []
    for online_item in Online_list:
        email = online_item[1]
        online_email.append(email)
    online_package['online'] = online_email
    online_package = json.dumps(online_package, ensure_ascii=False)
    online_package = online_package.encode()
    online_package_len = '{:<15}'.format(len(online_package))
    for online_item in Online_list:
        user_socket = online_item[0]
        try:
            user_socket.send(online_package_len.encode())
            user_socket.send(online_package)
        except Exception as e:
            print(e)

def personal_talk(recv_email, send_email, message):
    online_item = filter(lambda x: recv_email == x[1], Online_list)
    for item in online_item:
        data_sock = item[0]
    forward_package = dict()
    try:
        forward_package['personal_talk'] = send_email
        forward_package['message'] = message
        forward_package = json.dumps(forward_package,ensure_ascii=False)
        forward_package = forward_package.encode()
        forward_package_len = '{:<15}'.format(len(forward_package))
        data_sock.send(forward_package_len.encode())
        data_sock.send(forward_package)
    except Exception as e:
        print(e)            

def group_talk(send_email, message):
    online_item = filter(lambda x: send_email != x[1], Online_list)
    forward_package = dict()
    for i, item in enumerate(online_item):
        try:
            forward_package['group_talk'] = send_email
            forward_package['message'] = message
            forward_package = json.dumps(forward_package,ensure_ascii=False)
            forward_package = forward_package.encode()
            forward_package_len = '{:<15}'.format(len(forward_package))
            data_sock = item[0]
            data_sock.send(forward_package_len.encode())
            data_sock.send(forward_package)
        except Exception as e:
            print(e) 

def recv_files(file_sock, email):

    while True:
        action_len = file_sock.recv(15).decode()
        if not action_len:
            break
        action_len = int(action_len.strip())
        action = recved_main(action_len, file_sock)
        if 'personal_file' in action and 'send_ok' in action:
            action = json.loads(action)
            recv_email = action['personal_file']       
            file_name = action['file_name']
            file_size = action['file_size']
            file_md5 = action['file_md5']
            file_req = action['file_req']
            if recv_email != email:
                personal_file(recv_email, email, file_name, file_size, file_sock, file_req)
            
        elif 'personal_file' in action and 'recv_file' in action:
            action = json.loads(action)
            recv_email = action['personal_file']       
            recv_file = action['recv_file']
            file_req = action['file_req']
            file_name = action['file_name']
            file_size = action['file_size']
            if recv_email != email:
                threading.Thread(target=personal_recv, args=(recv_email, email, recv_file, file_req, file_sock, file_size, file_name)).start()
                #personal_recv(recv_email, email, recv_file, file_req, file_sock, file_size, file_name)
                
            
        # elif 'up_file' in action and 'file' in action:
        #     action = json.loads(action)
        #     recv_email = action['up_file']
        #     file_req = action['file_req']
        #     data = action['file']
        #     if recv_email != email:
        #         threading.Thread(target=upfile_file, args=(recv_email, email, data, file_req)).start()                

            
        elif 'up_file' in action and 'finish' in action:
            action = json.loads(action)
            recv_email = action['up_file']
            file_req = action['file_req']
            finish = action['finish']
            file_name = action['file_name']
            file_md5 = action['file_md5']
            if recv_email != email:
                threading.Thread(target=upfile_finish, args=(recv_email, email, finish, file_req, file_name, file_md5)).start()               
              
    


def personal_file(recv_email, send_email, file_name, file_size, sock, file_req):
    online_item = filter(lambda x: recv_email == x[1], File_list)
    for item in online_item:
        file_sock = item[0]
    forward_package = dict()
    try:
        forward_package['personal_file'] = send_email
        forward_package['file_name'] = file_name
        forward_package['file_size'] = file_size
        forward_package['file_req'] = file_req
        forward_package['send_ok'] = 1
        
        forward_package = json.dumps(forward_package,ensure_ascii=False)
        forward_package = forward_package.encode()
        forward_package_len = '{:<15}'.format(len(forward_package))
        file_sock.send(forward_package_len.encode())
        file_sock.send(forward_package)

        recv_size = 0
        while recv_size < file_size:
            file_tmp = sock.recv(file_size - recv_size)
            file_sock.send(file_tmp)
            if not file_tmp:
                break
            recv_size += len(file_tmp)
    except Exception as e:
        print(e)

def personal_recv(recv_email, send_email, recv_file, file_req, sock, file_size, file_name):
    online_item = filter(lambda x: recv_email == x[1], File_list)
    for item in online_item:
        file_so = item[0]
    forward_package = dict()
    try:
        forward_package['personal_file'] = send_email
        forward_package['recv_file'] = recv_file
        forward_package['file_req'] = file_req
        forward_package['file_name'] = file_name
        forward_package = json.dumps(forward_package,ensure_ascii=False)
        forward_package = forward_package.encode()
        forward_package_len = '{:<15}'.format(len(forward_package))
        file_so.send(forward_package_len.encode())
        file_so.send(forward_package)
    
        
        forward_package = dict()
        forward_package['server_send'] = 1
        forward_package['file_req'] = file_req
        forward_package['file_size'] = file_size
        forward_package['recv_email'] = recv_email
        forward_package['send_email'] = send_email
        forward_package['file_name'] = file_name
        
        forward_package = json.dumps(forward_package,ensure_ascii=False)
        forward_package = forward_package.encode()
        forward_package_len = '{:<15}'.format(len(forward_package))
        sock.send(forward_package_len.encode())
        sock.send(forward_package)

    except Exception as e:
        print(e)    

def upfile_file(recv_email, send_email, data, file_req):
    online_item = filter(lambda x: recv_email == x[1], File_list)
    for item in online_item:
        file_sock = item[0]
    forward_package = dict()
    try:
        forward_package['up_file'] = send_email
        forward_package['file'] = data
        forward_package['file_req'] = file_req

        forward_package = json.dumps(forward_package,ensure_ascii=False)
        forward_package = forward_package.encode()
        forward_package_len = '{:<15}'.format(len(forward_package))
        file_sock.send(forward_package_len.encode())
        file_sock.send(forward_package)
    except Exception as e:
        print(e)     

def upfile_finish(recv_email, send_email, finish, file_req, file_name, file_md5):
    online_item = filter(lambda x: recv_email == x[1], File_list)
    for item in online_item:
        file_sock = item[0]
    forward_package = dict()
    try:
        forward_package['up_file'] = send_email
        forward_package['finish'] = finish
        forward_package['file_req'] = file_req
        forward_package['file_name'] = file_name
        forward_package['file_md5'] = file_md5
        
        forward_package = json.dumps(forward_package,ensure_ascii=False)
        forward_package = forward_package.encode()
        forward_package_len = '{:<15}'.format(len(forward_package))
        file_sock.send(forward_package_len.encode())
        file_sock.send(forward_package)
    except Exception as e:
        print(e)     
            
def main():
    while True:
        conn, addr= log_reg_socket.accept()
        print(addr,"端口1已连接")
        threading.Thread(target=login_register, args=(conn,)).start()



if __name__ == '__main__':
    main()
