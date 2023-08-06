from PyQt5 import QtWidgets, QtCore, QtGui, Qt
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QFileDialog
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import os.path,re,threading,json,sys,time

from src.Ui_login import Ui_login
from src.Ui_register import Ui_register
from src.Ui_Forget_Password import Ui_Forget_Password
from src.Ui_Modify_Password import Ui_Modify_Password
from Ui_recv_win import Ui_recv_win
from src.Ui_window import Ui_window
from Mainwindow import Ui_MainWindow
from src.Ui_exp import Ui_exp
from src.Ui_record import Ui_record

import socket, hashlib

import client
import server_db,subprocess


import sys
import threading

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtCore import Qt, QPropertyAnimation, QRect, QEasingCurve
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QMainWindow, QApplication, QDesktopWidget, QListWidgetItem, QLabel, QWidget,QHBoxLayout, QFrame

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from api import *
sock_3 = socket.socket()
server = json.load(open('./client_config.json'))

def aes_encrypt(plaintext, key):
    # 使用 AES 加密算法进行加密
    backend = default_backend()
    iv = b"1234512345123451"  # 初始化向量 (IV)，16 字节长
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return base64.urlsafe_b64encode(ciphertext)

def aes_decrypt(ciphertext, key):
    # 使用 AES 加密算法进行解密
    backend = default_backend()
    iv = b"1234512345123451"  # 初始化向量 (IV)，16 字节长
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(base64.urlsafe_b64decode(ciphertext)) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

class Mylogin(QtWidgets.QMainWindow,Ui_login):
    def __init__(self) -> None:
        super(Mylogin,self).__init__()
        self.setupUi(self)
    
    def exit(self):
        self.close()
        client.exit()
        
    def min(self):
        self.showMinimized()
        
    def login(self):
        box = QtWidgets.QMessageBox()
        Email = self.Email_Text.text()
        password = self.Password_Text.text()
        try:
            if len(Email) == 0:
                box.warning(self,'Warning!',"邮箱不能为空！")
            elif len(password) == 0:
                box.warning(self,'Warning!',"密码不能为空！")
            elif not re.search('@', Email):
                box.warning(self, '提示', '邮箱格式有误！')
            elif not re.match("^[a-zA-Z0-9_]{0,12}$", password):
                box.warning(self, "提示", "密码输入格式有误!")
            else:
                args = dict()
                password = client.passwd_md5(password)
                args["Email"] = Email
                args["password"] = password
                response = client.login(args)
            
                if response == 0:
                    self.window_ui = MyMainForm(Email)
                    self.window_ui.show()                    
                    #登录成功
                    #打开聊天窗口
                    print("LOgin!")
                    self.close()
                elif response == 1:
                    box.warning(self, "Warning", "用户名或密码错误!")
                elif response == 2:
                    box.warning(self, "Warning", "用户名或密码错误!")
                elif response == 3:
                    box.warning(self, "Warning", "您已登录，无需重复登录！") 
        except Exception as e:
            print(e)       

    def register(self):
        self.register_ui = Myregister()
        self.register_ui.show()
        
    def modify_password(self):
        self.modify_password_ui = Mymodify_password()
        self.modify_password_ui.show()        
    
    def forget_password(self):
        self.forget_password_ui = Myforget_password()
        self.forget_password_ui.show()  
        
class Myregister(QtWidgets.QMainWindow,Ui_register):
    def __init__(self):
        super(Myregister, self).__init__()
        self.setupUi(self)
        
    def min(self):
        self.showMinimized()
        
    def register(self):
        try:
            box = QtWidgets.QMessageBox()
            Email = self.Email_Text.text()
            Name = self.Name_Text.text()
            Password = self.Password_Text.text()
            if Password != self.Password_confirm_Text.text():
                box.warning(self,'Warning!',"两次密码不一致！")
            elif len(Email) == 0:
                box.warning(self,'Warning!',"邮箱不能为空！")
            elif len(Password) == 0:
                box.warning(self,'Warning!',"密码不能为空！")
            elif not re.search('@', Email):
                box.warning(self, '提示', '邮箱格式有误！')
            elif not re.match("^[a-zA-Z0-9_]{0,12}$", Password):
                box.warning(self, "提示", "密码输入格式有误!")
            elif len(Name) > 10:
                box.warning(self,'提示','昵称太长')
            elif len(Name) == 0:
                box.warning(self, '提示', '昵称为空')
            else:
                args = dict()
                Password = client.passwd_md5(Password)
                args["Email"] = Email
                args["user_name"] = Name
                args["password"] = Password
                response = client.register(args)
                
                if response == 0:
                    box.information(self, "恭喜", "注册成功!")
                    self.close()
                elif response == 1:
                    box.warning(self, '警告', '该邮箱已存在!')
        except Exception as e:
            print(e)
                    
    def exit(self):
        self.close()  

class Myforget_password(QtWidgets.QMainWindow,Ui_Forget_Password):
    def __init__(self):
        super(Myforget_password, self).__init__()
        self.setupUi(self)
    
    def min(self):
        self.showMinimized()
    
    def modify_password(self):
        box = QtWidgets.QMessageBox()
        Email = self.Email_Text.text()
        Password_New = self.Password_New_Text.text()
        
        if len(Email) == 0:
            box.warning(self,'Warning!',"邮箱不能为空！")
        elif not re.search('@', Email):
            box.warning(self, '提示', '邮箱格式有误！')
        elif len(Password_New) == 0:
            box.warning(self,'Warning!',"密码不能为空！")
        elif not re.match("^[a-zA-Z0-9_]{0,12}$", Password_New):
            box.warning(self, "提示", "密码输入格式有误!")

        else:
            args = dict()
            args["Email"] = Email
            args["new_password"] = client.passwd_md5(Password_New) 
            response = client.forget_password(args)
            
            if response == 0:
                box.information(self, "恭喜", "密码重置成功!")
                self.close()
            elif response == 1:
                box.warning(self, "警告", "邮箱不存在!")
                
    def exit(self):
        self.close()  

class Mymodify_password(QtWidgets.QMainWindow,Ui_Modify_Password):
    def __init__(self):
        super(Mymodify_password, self).__init__()
        self.setupUi(self)
    
    def min(self):
        self.showMinimized()
        
    def modify_password(self):
        box = QtWidgets.QMessageBox()
        Email = self.Email_Text.text()
        Password_Old = self.Password_Old_Text.text()
        Password_New = self.Password_New_Text.text()
        if len(Email) == 0:
            box.warning(self,'Warning!',"邮箱不能为空！")
        elif not re.search('@', Email):
            box.warning(self, 'Warning!', '邮箱格式有误！')
        elif len(Password_Old) == 0:
            box.warning(self,'Warning!',"旧密码不能为空！")
        elif len(Password_New) == 0:
            box.warning(self,'Warning!',"新密码不能为空！")    
        elif not re.match("^[a-zA-Z0-9_]{0,12}$", Password_New):
            box.warning(self, "Warning!", "密码输入格式有误!")
        else:
            args = dict()
            Password_Old = client.passwd_md5(Password_Old)
            Password_New = client.passwd_md5(Password_New)
            args["Email"] = Email
            args["old_password"] = Password_Old
            args["new_password"] = Password_New
            response = client.modify_password(args)
            if response == 0:
                box.information(self, "恭喜", "修改密码成功!")
                self.close()
            elif response == 1:
                box.warning(self, "警告", "邮箱不存在!")
            elif response == 2:
                box.warning(self, "警告", "旧密码错误!")    
        
    def exit(self):
        self.close()          

class MyThread(QThread): 
    signal = pyqtSignal(str)  # 设置触发信号传递的参数数据类型,这里是字符串
    sock = socket.socket()

    def __init__(self):
        super(MyThread, self).__init__()


    def run(self):  # 在启动线程后任务从这个函数里面开始执行
        server = json.load(open('client_config.json'))
        self.sock.connect((server['server_IP'], server['server_port_2']))
        print('是否连接2')
        while True:    #不停的接消息
            while True:
                fan_len = self.sock.recv(15).decode()
                if not len(fan_len):
                    break
                fan_len = int(fan_len.strip())
                size = 0
                tmp = b''
                while size < fan_len:
                    data = self.sock.recv(fan_len - size)
                    if not data:
                        break
                    tmp += data
                    size += len(data)
                tmp = tmp.decode()
                self.signal.emit(str(tmp))    #把接到的消息返回

    def action(self,package):
        package = package.encode()
        package_len = '{:<15}'.format(len(package))        
        self.sock.send(package_len.encode())  # 发送报头长度
        self.sock.send(package)     #发送正文  
        
class MyThread_2(QThread):
    signal = pyqtSignal(str)  # 设置触发信号传递的参数数据类型,这里是字符串
    def __init__(self):
        super(MyThread_2, self).__init__()

    def run(self):  # 在启动线程后任务从这个函数里面开始执行
        week = ['一', '二', '三', '四', '五', '六', '日']
        while True:
            local_time = time.localtime()
            now_time = '%s/%s/%s %s:%s:%s 星期%s' % (local_time[:6] + (week[local_time[6]],))
            time.sleep(1)
            self.signal.emit(str(now_time))    #把接到的消息返回

class MyThread_3(QThread):
    signal = pyqtSignal(str)  # 设置触发信号传递的参数数据类型,这里是字符串


    def __init__(self):
        super(MyThread_3, self).__init__()


    def run(self):  # 在启动线程后任务从这个函数里面开始执行

        while True:    #不停的接消息
            while True:
                fan_len = sock_3.recv(15).decode()
                if not len(fan_len):
                    break
                fan_len = int(fan_len.strip())
                size = 0
                tmp = b''
                while size < fan_len:
                    data = sock_3.recv(fan_len - size)
                    if not data:
                        break
                    tmp += data
                    size += len(data)
                tmp = tmp.decode()
                if 'server_send' in tmp:
                    tmp = json.loads(tmp)
                    file_size = tmp['file_size']
                    recv_email = tmp['recv_email']
                    send_email = tmp['send_email']
                    file_name = tmp['file_name']
                    file_req = tmp['file_req']
                    curfile_name = file_name.strip().split('/')
                    qingqiu = curfile_name[-1]
                    file_path = './record_cache/' + send_email + '/' + recv_email[:5] +'__' + str(file_req)  + '__' + qingqiu
                    recv_size = 0
                    with open(file_path, 'wb')as f:
                        while recv_size < file_size:
                            file_tmp = sock_3.recv(file_size - recv_size)
                            f.write(file_tmp)
                            if not file_tmp:
                                break
                            recv_size += len(file_tmp)
                else:
                    self.signal.emit(str(tmp))#把接到的消息返回
                    
    
    def action(self,package):
        package = package.encode()
        package_len = '{:<15}'.format(len(package))        
        sock_3.send(package_len.encode())  # 发送报头长度
        sock_3.send(package)     #发送正文             

class Myrecvtalk(QMainWindow, Ui_recv_win):
    '''私人聊天'''

    send_info = ''
    name = ''
    def __init__(self, host_email, recv_email):
        super().__init__()
        #self.send_info = Myperson_file()
        
        self.setupUi(self)
        
        
        # self.mythread = MyThread_3()    #开启一个线程来接收消息
        # #self.mythread2 = MyThread_2()
        # self.mythread.signal.connect(self.callback)
        # #self.mythread2.signal.connect(self.callback2)
        # self.mythread.start()
        self.file_list = []
        self.file_req = 0
        
        self.host_email = host_email
        self.recv_email = recv_email
        self.recv_name = server_db.email2name(recv_email)
        self.host_name = server_db.email2name(host_email)
        self.NAME = server_db.email2name(recv_email).upper()
        self.name_first = self.NAME[0]
        img = "image: url(:/png/images/字母/" + self.name_first +".png);"
        self.widget.setStyleSheet(img)
        self.label_23.setText(self.recv_name)
        
        self.Oline = 0
        
        self.start_x = None
        self.start_y = None
        self.fixed_width = 710
        self.fixed_height = 569
        self.float_width = 357
        self.float_height = 100
        self.float_right_x = 14  # 右侧距离
        self.float_y = 500  # Y距离
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.setWindowFlags(Qt.FramelessWindowHint)  # 设置窗口标志：隐藏窗口边框
        self.animation_event = threading.Event()  # 动画信号
        self.float_state_event = threading.Event()  # 状态信号
        self.widget_3.setMaximumWidth(0)
        self.frame_2.setMaximumSize(0, 0)
        self.setGeometry(QRect(0, 0, 357, 75))
        self.pushButton_2.clicked.connect(self.widget_animation_start)
        self.pushButton.clicked.connect(self.float_animation_exit)
        self.pushButton_5.clicked.connect(self.exp_control)
        self.pushButton_6.clicked.connect(self.key_init)
        self.pushButton_7.clicked.connect(self.select_files)
        self.pushButton_8.clicked.connect(self.record_control)
        self.listWidget.itemClicked['QListWidgetItem*'].connect(self.recv_ok)
        self.record_win = None
        self.shared_key = None
        self.float_animation_start()
        # self.key_init()
        
    def key_init(self):
        if self.comboBox.currentText() in {'KYBER768_Mismatch','KYBER1024_Mismatch','KYBER512_Mismatch'}:
            with open("pk.txt", "r") as fp:
                pk_str = fp.read()

            # 将 CSV 格式的字符串转换为 Python 列表
            pk_list = [int(x) for x in pk_str.split(",")]
            
            with open("sk.txt", "r") as fp:
                sk_str = fp.read()

            # 将 CSV 格式的字符串转换为 Python 列表
            sk_list = [int(x) for x in sk_str.split(",")]
            
            self.pk = (ctypes.c_uint8 * CRYPTO_PUBLICKEYBYTES)(*pk_list)
            self.sk = (ctypes.c_uint8 * CRYPTO_SECRETKEYBYTES)(*sk_list)
            self.skpoly = polyvec()

            pk_bytes = bytearray(self.pk)
            base64_encoded = base64.b64encode(pk_bytes).decode('utf-8')
            print('生成公钥：' + base64_encoded)
            sk_bytes = bytearray(self.sk)
            base64_encoded1 = base64.b64encode(sk_bytes).decode('utf-8')
            print('生成私钥：' + base64_encoded1)
            
            send_new = 'KEYINIT: ' + str(base64_encoded)
            
            frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
            self.generate_text_frame_self(frame_27,send_new[:20], self.host_email)
            self.verticalLayout_21.addWidget(frame_27)        
            new_dict = dict()
            new_dict['personal_talk'] = self.recv_email
            new_dict['message'] = send_new
            news = json.dumps(new_dict, ensure_ascii=False)
            MyThread().action(news)   
            
            time.sleep(5)
            print("检测到重用公钥")
            print("开始发起query")
            # 启动 server 子进程
            server_process = subprocess.Popen('./server', shell=True)

            # 启动 client 子进程
            client_process = subprocess.Popen('./client', shell=True)

            # 等待 server 和 client 进程完成
            server_process.wait()
            client_process.wait()
        elif self.comboBox.currentText() in {'KYBER768_Recovery','KYBER512_Recovery','KYBER1024_Recovery'} :
            with open("pk.txt", "r") as fp:
                pk_str = fp.read()

            # 将 CSV 格式的字符串转换为 Python 列表
            pk_list = [int(x) for x in pk_str.split(",")]
            
            with open("sk.txt", "r") as fp:
                sk_str = fp.read()

            # 将 CSV 格式的字符串转换为 Python 列表
            sk_list = [int(x) for x in sk_str.split(",")]
            
            self.pk = (ctypes.c_uint8 * CRYPTO_PUBLICKEYBYTES)(*pk_list)
            self.sk = (ctypes.c_uint8 * CRYPTO_SECRETKEYBYTES)(*sk_list)
            self.skpoly = polyvec()

            pk_bytes = bytearray(self.pk)
            base64_encoded = base64.b64encode(pk_bytes).decode('utf-8')
            print('生成公钥：' + base64_encoded)
            sk_bytes = bytearray(self.sk)
            base64_encoded1 = base64.b64encode(sk_bytes).decode('utf-8')
            print('生成私钥：' + base64_encoded1)
            
            send_new = 'KEYINIT: ' + str(base64_encoded)
            
            frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
            self.generate_text_frame_self(frame_27,send_new[:20], self.host_email)
            self.verticalLayout_21.addWidget(frame_27)        
            new_dict = dict()
            new_dict['personal_talk'] = self.recv_email
            new_dict['message'] = send_new
            news = json.dumps(new_dict, ensure_ascii=False)
            MyThread().action(news)   
            
            time.sleep(5)
            print("检测到重用公钥")
            print("开始发起query")
            os.system('./recovery')
        elif self.comboBox.currentText() in {'KYBER768','KYBER512','KYBER1024','Normal'}:
            self.pk = (ctypes.c_uint8 * CRYPTO_PUBLICKEYBYTES)()
            self.sk = (ctypes.c_uint8 * CRYPTO_SECRETKEYBYTES)()
            self.skpoly = polyvec()

            crypto_kem_keypair(self.pk, self.sk, ctypes.byref(self.skpoly))
            pk_bytes = bytearray(self.pk)
            base64_encoded = base64.b64encode(pk_bytes).decode('utf-8')
            print('生成公钥：' + base64_encoded)
            sk_bytes = bytearray(self.sk)
            base64_encoded1 = base64.b64encode(sk_bytes).decode('utf-8')
            print('生成私钥：' + base64_encoded1)
            
            send_new = 'KEYINIT: ' + str(base64_encoded)
            
            frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
            self.generate_text_frame_self(frame_27,send_new[:20], self.host_email)
            self.verticalLayout_21.addWidget(frame_27)        
            new_dict = dict()
            new_dict['personal_talk'] = self.recv_email
            new_dict['message'] = send_new
            news = json.dumps(new_dict, ensure_ascii=False)
            MyThread().action(news)        
        
        elif self.comboBox.currentText() in {'KYBER768_Backdoor','KYBER512_Backdoor','KYBER1024_Backdoor'}:
            with open("pk.txt", "r") as fp:
                pk_str = fp.read()

            # 将 CSV 格式的字符串转换为 Python 列表
            pk_list = [int(x) for x in pk_str.split(",")]
            
            with open("sk.txt", "r") as fp:
                sk_str = fp.read()

            # 将 CSV 格式的字符串转换为 Python 列表
            sk_list = [int(x) for x in sk_str.split(",")]
            
            self.pk = (ctypes.c_uint8 * CRYPTO_PUBLICKEYBYTES)()
            self.sk = (ctypes.c_uint8 * CRYPTO_SECRETKEYBYTES)()
            self.skpoly = polyvec()

            crypto_kem_keypair(self.pk, self.sk, ctypes.byref(self.skpoly))
            pk_bytes = bytearray(self.pk)
            base64_encoded = base64.b64encode(pk_bytes).decode('utf-8')
            print('生成公钥：' + base64_encoded)
            sk_bytes = bytearray(self.sk)
            base64_encoded1 = base64.b64encode(sk_bytes).decode('utf-8')
            print('生成私钥：' + base64_encoded1)
            
            send_new = 'KEYINIT: ' + str(base64_encoded)
            
            frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
            self.generate_text_frame_self(frame_27,send_new[:20], self.host_email)
            self.verticalLayout_21.addWidget(frame_27)        
            new_dict = dict()
            new_dict['personal_talk'] = self.recv_email
            new_dict['message'] = send_new
            news = json.dumps(new_dict, ensure_ascii=False)
            MyThread().action(news) 
            
            time.sleep(5)
            print("检测到公钥中的后门")
            print("计算私钥...")
            os.system('./recovery')
        
        
    def up_file(self, recv_email,file_req):
        file_dict = self.file_list[file_req]
        file_name = file_dict['file_name']
        file_size = file_dict['file_size']
        self.Oline = 1
        with open(file_name, 'rb')as s:
                while True:
                    data = s.read(1024)
                    if not data:
                        break
                    sock_3.send(data)
                    
                    
        curfile_name = file_name.strip().split('/')
        qingqiu = curfile_name[-1]        
        send_new = "文件"+ qingqiu + "发送完成"                                        
        new_dict = dict()
        new_dict['personal_talk'] = self.recv_email
        new_dict['message'] = send_new
        news = json.dumps(new_dict, ensure_ascii=False)
        MyThread().action(news)
        
        
        reg = dict()
        reg['up_file'] = self.recv_email
        reg['file_req'] = file_req
        reg['file_name'] = file_name
        reg['file_md5'] = file_dict['file_md5']
        reg['finish'] = 1 #发送结束
        reg = json.dumps(reg, ensure_ascii=False)
        MyThread_3().action(reg)        
        self.Oline = 0
        
        frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
        self.generate_text_frame_self(frame_27,send_new, self.host_email)
        self.verticalLayout_21.addWidget(frame_27)

    def jietu_control(self):
        box = QtWidgets.QMessageBox()
        box.warning(self,'Warning!',"截图功能还未开发")           
            
    def exp_control(self):
        self.exp_c = Myexp(self.x(), self.y(), self.textEdit_2)
        self.exp_c.show()

    def record_control(self):
        self.record_win = Myrecord(self.host_email, self.recv_email)
        self.record_win.show()

    def send_action(self):
        try:
            send_new = self.textEdit_2.toPlainText()
                        
            local_time = time.localtime()
            now_time = '%s/%s/%s %s:%s:%s' % (local_time[:6])
            req = now_time + ':' + self.host_email + ':' + send_new
            record_path = './record_cache/' + self.host_email + '/' + self.recv_email + '.txt'
            with open(record_path, 'a', encoding='utf-8')as h:
                h.write(req + '\n')
            
            if send_new != '':
                
                emode = self.comboBox.currentText()
                frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                self.generate_text_frame_self(frame_27,send_new, self.host_email)
                self.verticalLayout_21.addWidget(frame_27)
                self.textEdit_2.clear()
                if emode in {'Normal'}:
                    pass
                if emode != 'Normal':
                    if self.shared_key != None:
                        send_new = 'ENCRYPT:' + str(aes_encrypt(send_new.encode() ,self.shared_key))
                        frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                        self.generate_text_frame_self(frame_27,send_new, self.host_email)
                        self.verticalLayout_21.addWidget(frame_27)
                        print(send_new)
                        req = now_time + ':' + self.host_email + ':' + send_new
                        with open('third.txt','a',encoding='utf-8') as f:
                            f.write(req+'\n')
                new_dict = dict()
                new_dict['personal_talk'] = self.recv_email
                new_dict['message'] = send_new
                news = json.dumps(new_dict, ensure_ascii=False)
                MyThread().action(news)
        except Exception as e:
            print(e)

    def text_changed(self):
        msg = self.textEdit_2.toPlainText()
        if '\n' in msg:
            msg = msg.replace('\n', '')
            self.textEdit_2.setText(msg)
            self.send_action()
      
    def select_files(self):
        '''选择文件'''
        try:
            box = QtWidgets.QMessageBox()
            if self.Oline == 1:
                box.warning(self, '警告', '文件上传中，请稍后重试!')
            else:
                # self.Oline = 1  #代表文件端口已连接
                dif = QFileDialog()
                dif.setFileMode(QFileDialog.AnyFile)    #设置打开任意文件
                dif.setFilter(QDir.Files)  #文件过滤
                if dif.exec_():
                    # 接受选中文件的路径，默认为列表
                    file_path = dif.selectedFiles()   #获得文件绝对路径
                    # file_name = os.path.basename(file_path[0])        #获得文件名
                #self.textBrowser.setText(file_path[0])
                file_size = os.path.getsize(file_path[0])  # 获取文件大小
                #new_file_size = round(file_size / 1024 / 1024, 2)
                #new_file_size = '文件大小:' + str(new_file_size) + 'MB'
                #self.textBrowser_2.append(new_file_size)
                #print(new_file_size)
                file_md5 = self.file_md5(file_path[0])
                #self.textBrowser_2.append('文件md5为:' + file_md5)
                file_dict = dict()
                file_dict['file_name']= file_path[0]
                file_dict['file_size']= file_size
                file_dict['file_md5']= file_md5
                self.file_list.append(file_dict)
                reg = dict()
                reg['personal_file'] = self.recv_email
                reg['file_name'] = file_path[0]
                reg['file_size'] = file_size
                reg['file_md5']  = file_md5
                reg['file_req'] = self.file_req
                reg['send_ok'] = 1
                self.file_req = self.file_req + 1
                reg = json.dumps(reg, ensure_ascii=False)
                MyThread_3().action(reg)
                curfile_name = file_path[0].strip().split('/')
                qingqiu = curfile_name[-1]
                send_new = "发送文件" + qingqiu
                frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                self.generate_text_frame_self(frame_27,send_new, self.host_email)
                self.verticalLayout_21.addWidget(frame_27)
                
                
                
        except Exception as f:
            print(f)

    def recv_ok(self, item):
        reg = dict()
        reg['personal_file'] = self.recv_email
        reg['recv_file'] = 1
        reg['file_name'] = item.file_name
        reg['file_size'] = item.file_size
        reg['file_req'] = self.file_req
        reg = json.dumps(reg, ensure_ascii=False)
        MyThread_3().action(reg)
        send_new = "接受文件" + item.text()
        frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
        self.generate_text_frame_self(frame_27,send_new, self.host_email)
        self.verticalLayout_21.addWidget(frame_27)
        self.listWidget.takeItem(self.file_req)
        
    def file_md5(self, file_path):
        m = hashlib.md5()
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(1024)
                if not data:
                    break
                m.update(data)
        return m.hexdigest().upper()

    def notice_small(self):
        self.frame.setMaximumSize(16777, 16777)
        self.frame_2.setMaximumSize(0, 0)

    def notice_big(self):
        self.frame.setMaximumSize(0, 0)
        self.frame_2.setMaximumSize(16777, 16777)

    def widget_animation_start(self):
        if self.animation_event.is_set():
            return
        else:
            if self.widget_3.maximumWidth() == 0:
                self.widget_style_right(self.pushButton_2)
                self.animation_event.set()
                widget = QPropertyAnimation(self.widget_3, b"maximumWidth", self)
                widget.setStartValue(0)
                widget.setEndValue(200)
                widget.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
                widget.setDuration(400)
                widget.finished.connect(self.widget_animation_start_Signal)
                widget.start()
            else:
                self.widget_style_left(self.pushButton_2)
                self.animation_event.set()
                widget = QPropertyAnimation(self.widget_3, b"maximumWidth", self)
                widget.setStartValue(200)
                widget.setEndValue(0)
                widget.setDuration(400)
                widget.finished.connect(self.widget_animation_start_Signal)
                widget.start()

    def widget_animation_start_Signal(self):
        self.animation_event.clear()
        print(self.widget_3.maximumWidth())

    def float_animation_start(self):
        """主页"""
        if self.animation_event.is_set():
            return
        else:
            self.animation_event.set()
            if self.float_state_event.is_set():
                self.notice_small()
                notice = QPropertyAnimation(self, b"geometry", self)
                notice.setStartValue(
                    QRect(QDesktopWidget().screenGeometry().width() + self.float_width, self.float_y, self.float_width,
                          self.float_height))
                notice.setEndValue(
                    QRect(QDesktopWidget().screenGeometry().width() - self.float_width - self.float_right_x,
                          self.float_y, self.float_width, self.float_height))
                notice.setDuration(800)
                notice.finished.connect(self.float_animation_start_Signal)
                notice.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
                notice.start()

                notice = QPropertyAnimation(self, b"windowOpacity", self)
                notice.setStartValue(0)
                notice.setEndValue(1)
                notice.setDuration(200)
                notice.start()
            else:
                self.notice_big()
                notice = QPropertyAnimation(self, b"geometry", self)
                notice.setStartValue(QRect(self.x(), self.y(), 0, 0))
                notice.setEndValue(QRect(self.x(), self.y(), self.fixed_width, self.fixed_height))
                notice.setDuration(400)
                notice.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
                notice.finished.connect(self.float_animation_start_Signal)
                notice.start()

                notice = QPropertyAnimation(self, b"windowOpacity", self)
                notice.setStartValue(0)
                notice.setEndValue(1)
                notice.setDuration(200)
                notice.start()

    def float_animation_start_Signal(self):
        self.animation_event.clear()

    def float_animation_exit(self):
        if self.animation_event.is_set():
            return
        else:
            self.animation_event.set()
            if self.float_state_event.is_set():
                notice = QPropertyAnimation(self, b"geometry", self)
                notice.setStartValue(QRect(self.x(), self.y(), self.float_width, self.float_height))
                notice.setEndValue(
                    QRect(self.x() + self.float_width + 24, self.y(), self.float_width, self.float_height))
                notice.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
                notice.setDuration(800)
                notice.finished.connect(self.float_animation_exit_Signal)
                notice.start()
            else:
                notice = QPropertyAnimation(self, b"windowOpacity", self)
                notice.setStartValue(1)
                notice.setEndValue(0)
                notice.setDuration(800)
                notice.finished.connect(self.float_animation_exit_Signal)
                notice.start()

    def float_animation_exit_Signal(self):
        self.animation_event.clear()
        try:
            list = filter(lambda x: self.recv_email == x[1], MyMainForm.dyname_win)
            for li in list:
                obj = li
            obj[2] = 0
        except Exception as e:
            print(e)
        if self.record_win != None:
            self.record_win.close()
        self.close()

    def float_recovery_animation(self):
        """复原"""
        if self.animation_event.is_set():
            return
        else:
            self.notice_small()
            self.animation_event.set()
            notice = QPropertyAnimation(self, b"geometry", self)
            notice.setStartValue(QRect(self.x(), self.y(), self.width(), self.height()))
            notice.setEndValue(
                QRect(QDesktopWidget().screenGeometry().width() - self.float_width - self.float_right_x, self.float_y,
                      self.float_width, self.float_height))
            notice.setDuration(800)
            notice.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
            notice.finished.connect(self.animation_event.clear)
            notice.start()

    def float_deformation_animation(self):
        """变形"""
        if self.animation_event.is_set():
            return
        else:
            self.notice_big()
            self.animation_event.set()
            notice = QPropertyAnimation(self, b"geometry", self)
            notice.setStartValue(QRect(self.x(), self.y(), self.float_width, self.float_height))
            notice.setEndValue(QRect(self.x(), self.y(), self.fixed_width, self.fixed_height))
            notice.setDuration(400)
            notice.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
            notice.finished.connect(self.animation_event.clear)
            notice.start()

    def mouseReleaseEvent(self, event):
        if self.animation_event.is_set():
            return
        else:
            if self.float_state_event.is_set():
                if self.x() > QDesktopWidget().screenGeometry().width() / 5 * 4:
                    if self.animation_event.is_set():
                        return
                    self.float_recovery_animation()
                    self.float_state_event.set()
                else:
                    if self.animation_event.is_set():
                        return
                    self.float_deformation_animation()
                    self.float_state_event.clear()
            else:
                if self.x() + self.width() > QDesktopWidget().screenGeometry().width() / 10 * 9:
                    if self.animation_event.is_set():
                        return
                    self.float_recovery_animation()
                    self.float_state_event.set()

            self.start_x = None
            self.start_y = None

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            #super(Ui_recv_win, self).mousePressEvent(event)
            self.start_x = event.x()
            self.start_y = event.y()

    def mouseMoveEvent(self, event): 
        if self.animation_event.is_set():
            return
        else:
            try:
                #super(Ui_recv_win, self).mouseMoveEvent(event)
                dis_x = event.x() - self.start_x
                dis_y = event.y() - self.start_y
                self.move(self.x() + dis_x, self.y() + dis_y)
            except:
                pass

    def generate_text_frame(self, frame_23, message, email):
        frame_23.setMinimumSize(QtCore.QSize(0, 50))
        frame_23.setStyleSheet("")
        frame_23.setFrameShape(QtWidgets.QFrame.StyledPanel)
        frame_23.setFrameShadow(QtWidgets.QFrame.Raised)
        frame_23.setObjectName("frame_23")
        horizontalLayout_28 = QtWidgets.QHBoxLayout(frame_23)
        horizontalLayout_28.setContentsMargins(0, 0, 0, 0)
        horizontalLayout_28.setSpacing(12)
        horizontalLayout_28.setObjectName("horizontalLayout_28")
        frame_24 = QtWidgets.QFrame(frame_23)
        frame_24.setMinimumSize(QtCore.QSize(32, 32))
        
        
        name = self.recv_name.upper()
        name_first = name[0]
        img = "image: url(:/png/images/字母/" + name_first +".png);"
        
        frame_24.setStyleSheet(img)
        frame_24.setFrameShape(QtWidgets.QFrame.NoFrame)
        frame_24.setFrameShadow(QtWidgets.QFrame.Raised)
        frame_24.setObjectName("frame_24")
        horizontalLayout_28.addWidget(frame_24)
        plainTextEdit = QtWidgets.QPlainTextEdit(frame_23)
        plainTextEdit.setAcceptDrops(False)
        plainTextEdit.setStyleSheet("text-align: right;\n"
"border-radius: 20px;\n"
"background-color: rgb(255, 255, 255);\n"
"padding:10px;")
        plainTextEdit.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        plainTextEdit.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        plainTextEdit.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustIgnored)
        plainTextEdit.setTabChangesFocus(False)
        plainTextEdit.setDocumentTitle("")
        plainTextEdit.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
        plainTextEdit.setReadOnly(True)
        plainTextEdit.setOverwriteMode(False)
        plainTextEdit.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        plainTextEdit.setBackgroundVisible(False)
        plainTextEdit.setCenterOnScroll(False)
        plainTextEdit.setObjectName("plainTextEdit")
        plainTextEdit.setPlainText(message)
        
        f = QFont()
        f.setPointSize(14)
        f.setFamily("Agency FB")
        plainTextEdit.setFont(f)
        
        horizontalLayout_28.addWidget(plainTextEdit)
        horizontalLayout_28.setStretch(0, 1)
        horizontalLayout_28.setStretch(1, 10)
    
    def generate_text_frame_self(self, frame_27, message, email):
        frame_27.setMinimumSize(QtCore.QSize(0, 50))
        frame_27.setFrameShape(QtWidgets.QFrame.StyledPanel)
        frame_27.setFrameShadow(QtWidgets.QFrame.Raised)
        frame_27.setObjectName("frame_27")
        horizontalLayout_30 = QtWidgets.QHBoxLayout(frame_27)
        horizontalLayout_30.setContentsMargins(0, 0, 0, 0)
        horizontalLayout_30.setSpacing(12)
        horizontalLayout_30.setObjectName("horizontalLayout_30")
        plainTextEdit_3 = QtWidgets.QPlainTextEdit(frame_27)
        plainTextEdit_3.setAcceptDrops(False)
        plainTextEdit_3.setLayoutDirection(QtCore.Qt.LeftToRight)
        plainTextEdit_3.setStyleSheet("text-align: right;\n"
"border-radius: 20px;\n"
"background-color: rgb(255, 255, 255);\n"
"padding:10px;")
        plainTextEdit_3.setFrameShape(QtWidgets.QFrame.NoFrame)
        plainTextEdit_3.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        plainTextEdit_3.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        plainTextEdit_3.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
        plainTextEdit_3.setReadOnly(True)
        plainTextEdit_3.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        plainTextEdit_3.setObjectName("plainTextEdit_3")
        plainTextEdit_3.setPlainText(message)
        horizontalLayout_30.addWidget(plainTextEdit_3)
        frame_28 = QtWidgets.QFrame(frame_27)
        frame_28.setMinimumSize(QtCore.QSize(32, 0))
        
        name = self.host_name.upper()
        name_first =name[0]
        img = "image: url(:/png/images/字母/" + name_first +".png);"
        
        f = QFont()
        f.setPointSize(14)
        f.setFamily("Agency FB")
        plainTextEdit_3.setFont(f)
        
        frame_28.setStyleSheet(img)
        frame_28.setFrameShape(QtWidgets.QFrame.NoFrame)
        frame_28.setFrameShadow(QtWidgets.QFrame.Raised)
        frame_28.setObjectName("frame_28")
        horizontalLayout_30.addWidget(frame_28)
        horizontalLayout_30.setStretch(0, 10)
        horizontalLayout_30.setStretch(1, 1)
   
    @staticmethod
    def widget_style_left(widget):
        style = """QPushButton{
            margin-right:3px;
            margin-bottom:0px;
            color: rgb(255, 255, 255);
            image: url(:/svg/images/svg/double-left.svg);
            border:1px outset rgb(255, 255, 255);
            border-radius:8px;
        }
        QPushButton:hover {
        
        border:2px outset rgba(36, 36, 36,0);
        }
        QPushButton:pressed {
        
        border:4px outset rgba(36, 36, 36,0);
        }"""
        widget.setStyleSheet(style)


    @staticmethod
    def widget_style_right(widget):
        style = """QPushButton{
            margin-right:3px;
            margin-bottom:0px;
            color: rgb(255, 255, 255);
            image: url(:/svg/images/svg/double-right.svg);
            border:1px outset rgb(255, 255, 255);
            border-radius:8px;
        }
        QPushButton:hover {

        border:2px outset rgba(36, 36, 36,0);
        }
        QPushButton:pressed {

        border:4px outset rgba(36, 36, 36,0);
        }"""
        widget.setStyleSheet(style)

class MyMainForm(QMainWindow, Ui_MainWindow):
    dyname_win = []
    people = []
    
    def __init__(self, email, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        
        sock_3.connect(("127.0.0.1", server['server_port_3']))
        
        self.email = email
        self.name = server_db.email2name(email)
        self.NAME = server_db.email2name(email).upper()
        self.name_first = self.NAME[0]
        img = "image: url(:/png/images/字母/" + self.name_first +".png);"
        self.widget.setStyleSheet(img)
        self.label_23.setText(self.name)
        
        self.mythread = MyThread()    #开启一个线程来接收消息
        #self.mythread2 = MyThread_2()
        self.mythread_3 = MyThread_3()
        self.mythread.signal.connect(self.callback)
        self.mythread_3.signal.connect(self.callback3)
        #self.mythread2.signal.connect(self.callback2)
        self.mythread.start()
        self.mythread_3.start()
        #self.mythread2.start()
        
        
        
        self.start_x = None
        self.start_y = None
        self.fixed_width = 710
        self.fixed_height = 569
        self.float_width = 357
        self.float_height = 75
        self.float_right_x = 14  # 右侧距离
        self.float_y = 113  # Y距离
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.setWindowFlags(Qt.FramelessWindowHint)  # 设置窗口标志：隐藏窗口边框
        self.animation_event = threading.Event()  # 动画信号
        self.float_state_event = threading.Event()  # 状态信号
        self.widget_3.setMaximumWidth(0)
        self.frame_2.setMaximumSize(0, 0)
        self.setGeometry(QRect(0, 0, 357, 75))
        self.pushButton_2.clicked.connect(self.widget_animation_start)
        self.pushButton.clicked.connect(self.float_animation_exit)
        self.pushButton_5.clicked.connect(self.exp_control)
        self.pushButton_6.clicked.connect(self.jietu_control)
        self.pushButton_7.clicked.connect(self.select_files)
        self.pushButton_8.clicked.connect(self.record_control)
        self.record_win = None
        self.float_animation_start()

        
        personal_record_cache = "./record_cache/" + email
        if not os.path.exists(personal_record_cache):
            os.mkdir(personal_record_cache)
    
    def exp_control(self):
        self.exp_c = Myexp(self.x(), self.y(), self.textEdit_2)
        self.exp_c.show()
    
    def record_control(self):
        self.record_win = Myrecord('@', '@')
        self.record_win.show()
    
    def jietu_control(self):
        box = QtWidgets.QMessageBox()
        box.warning(self,'Warning!',"截图功能还未开发")        
    
    def callback3(self, tmp):
        try:
            if 'personal_file' in tmp and 'send_ok' in tmp:
                request_name = json.loads(tmp)
                send_email = request_name['personal_file']
                file_name  = request_name['file_name']
                file_size = request_name['file_size']
                file_req = request_name['file_req']
                
                ld = filter(lambda x: send_email == x[1], MyMainForm.dyname_win)    #判断来自对方的消息的窗口是否打开，如果打开则在上面添加消息，否则重新打开窗口添加消息
                for l in ld:
                    obj = l
                    
                
                if obj[2] == 1:    #当窗口存在直接添加消息
                    name = file_name.upper()
                    name_first = name[-2]
                    img = ":/png/images/字母/" + name_first + ".png"
                    item = QtWidgets.QListWidgetItem()
                    icon = QtGui.QIcon()
                    icon.addPixmap(QtGui.QPixmap(img), QtGui.QIcon.Normal, QtGui.QIcon.Off)
                    item.setIcon(icon)
                    curfile_name = file_name.strip().split('/')
                    qingqiu = curfile_name[-1]
                    item.setText(qingqiu)
                    
                    f = QFont()
                    f.setPointSize(10)
                    f.setFamily("Agency FB")
                    item.setFont(f)
                    
                    item.file_name = file_name
                    item.send_email = send_email
                    item.file_req = file_req
                    item.file_size = file_size
                    news = "发送文件" + qingqiu
                    frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                    self.generate_text_frame(frame_23, news, send_email)
                    obj[0].verticalLayout_21.addWidget(frame_23)
                    
                    obj[0].listWidget.addItem(item)

                elif obj[2] == 0:   #当窗口不存在
                    obj[2] = 1    #打开窗口
                    obj[0].show()
                    name = file_name.upper()
                    name_first = name[-2]
                    img = ":/png/images/字母/" + name_first + ".png"
                    item = QtWidgets.QListWidgetItem()
                    icon = QtGui.QIcon()
                    icon.addPixmap(QtGui.QPixmap(img), QtGui.QIcon.Normal, QtGui.QIcon.Off)
                    item.setIcon(icon)
                    curfile_name = file_name.strip().split('/')
                    qingqiu = curfile_name[-1]
                    item.setText(qingqiu)
                    f = QFont()
                    f.setPointSize(10)
                    f.setFamily("Agency FB")
                    item.setFont(f)
                    item.file_name = file_name                   
                    item.send_email = send_email
                    item.file_req = file_req
                    item.file_size = file_size
                    news = "发送文件" + qingqiu
                    frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                    self.generate_text_frame(frame_23, news, send_email)
                    obj[0].verticalLayout_21.addWidget(frame_23)                    
                    obj[0].listWidget.addItem(item)
                
            
            elif 'personal_file' in tmp and 'recv_file' in tmp:
                request_name = json.loads(tmp)
                send_email = request_name['personal_file']
                recv_file = request_name['recv_file']
                file_req = request_name['file_req']
                ld = filter(lambda x: send_email == x[1], MyMainForm.dyname_win)    #判断来自对方的消息的窗口是否打开，如果打开则在上面添加消息，否则重新打开窗口添加消息
                for l in ld:
                    obj = l
                if recv_file == 1:
                    file_name = request_name['file_name']
                    curfile_name = file_name.strip().split('/')
                    qingqiu = curfile_name[-1]
                    news = "接受文件" + qingqiu
                    frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                    self.generate_text_frame(frame_23, news, send_email)
                    obj[0].verticalLayout_21.addWidget(frame_23)
                    
                    obj[0].up_file(send_email, file_req)
            
            # elif 'up_file' in tmp and 'file' in tmp:
            #     request_name = json.loads(tmp)
            #     file_req = request_name['file_req']
            #     send_email = request_name['up_file']
            #     data = bytes(request_name['file'].encode())
            #     ld = filter(lambda x: send_email == x[1], MyMainForm.dyname_win)    #判断来自对方的消息的窗口是否打开，如果打开则在上面添加消息，否则重新打开窗口添加消息
            #     for l in ld:
            #         obj = l
            #     file_name = obj[0].file_list[file_req]['file_name']
            #     curfile_name = file_name.strip().split('/')
            #     qingqiu = curfile_name[-1]
            #     file_path = './record_cache/' + self.email + '/' + send_email[:5] +'__' + str(file_req)  + '__' + qingqiu       
                
            #     with open(file_path, 'ab')as f:
            #         f.write(data)    
                
            elif 'up_file' in tmp and 'finish' in tmp:
                request_name = json.loads(tmp)
                file_req = request_name['file_req']
                send_email = request_name['up_file']
                ld = filter(lambda x: send_email == x[1], MyMainForm.dyname_win)    #判断来自对方的消息的窗口是否打开，如果打开则在上面添加消息，否则重新打开窗口添加消息
                for l in ld:
                    obj = l
                    
                file_name = request_name['file_name']
                curfile_name = file_name.strip().split('/')
                qingqiu = curfile_name[-1]
                file_path = './record_cache/' + self.email + '/' + send_email[:5] +'__' + str(file_req)  + '__' + qingqiu
                file_md5_recv = obj[0].file_md5(file_path)
                
                file_md5_send = request_name['file_md5']
                if file_md5_recv == file_md5_send:
                    news = qingqiu + "接受成功"
                    
                    frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                    self.generate_text_frame_self(frame_27, news, self.email)
                    obj[0].verticalLayout_21.addWidget(frame_27)
                    
                    new_dict = dict()
                    new_dict['personal_talk'] = send_email
                    new_dict['message'] = news
                    news = json.dumps(new_dict, ensure_ascii=False)
                    MyThread().action(news)
                    
                
                else:
                    news = qingqiu + "接受失败,请再次发送"
                    frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                    self.generate_text_frame_self(frame_27, news, self.email)
                    obj[0].verticalLayout_21.addWidget(frame_27)
                    
                    new_dict = dict()
                    new_dict['personal_talk'] = send_email
                    new_dict['message'] = news
                    news = json.dumps(new_dict, ensure_ascii=False)
                    MyThread().action(news)
            
            
            
        except Exception as e:
            print(e)  
                 
    def callback(self, tmp):  # 这里的 i 就是任务线程传回的数据
        try:
            if 'online' in tmp:             #返回显示在线人数
                tmp = json.loads(tmp)
                list = tmp['online']     #在线邮箱列表
                for k, p in enumerate(list):
                    if p not in MyMainForm.people:
                        name = server_db.email2name(p).upper()
                        name_first = name[0]
                        img = ":/png/images/字母/" + name_first + ".png"
                        item = QtWidgets.QListWidgetItem()
                        icon = QtGui.QIcon()
                        icon.addPixmap(QtGui.QPixmap(img), QtGui.QIcon.Normal, QtGui.QIcon.Off)
                        item.setIcon(icon)
                        item.email = p
                        item.setText(server_db.email2name(p))
                        self.listWidget.addItem(item)
                        
                        MyMainForm.people.append(p)
                        pp = Myrecvtalk(self.email, p)
                        MyMainForm.dyname_win.append([pp, list[k], 0])

                # if self.PEOPLE == 0:
                #     for i, j in enumerate(list):      #为每个用户按钮附上用户名
                #         MyQtWidgets.people.append(j)
                #         j = Myrecvtalk()
                #         MyQtWidgets.dyname_win.append([j, list[i], 0])      #每个用户的对象名，用户名，窗口状态0/1（0表示窗口关闭，1表示开启）
                #         self.PEOPLE = 1
                # print(MyQtWidgets.dyname_win,1)
            elif 'down_line' in tmp:
                dict_name = json.loads(tmp)
                email = dict_name['down_line']
                down_action = email + '下线!'

                MyMainForm.people.remove(email)
                down_user = filter(lambda x: email == x[1], MyMainForm.dyname_win)
                for i in down_user:
                    down_p = i
                self.listWidget.takeItem(MyMainForm.dyname_win.index(down_p))
                MyMainForm.dyname_win.remove(down_p)



            elif 'personal_talk' in tmp:
                request_name = json.loads(tmp)
                other_name = request_name['personal_talk']
                news = request_name['message']
                
                local_time = time.localtime()
                now_time = '%s/%s/%s %s:%s:%s' % (local_time[:6])
                req = now_time + ':' + other_name + ':' + news
                record_path = './record_cache/' + self.email + '/' + other_name + '.txt'
                with open(record_path, 'a', encoding='utf-8')as h:
                    h.write(req + '\n')
                
                ld = filter(lambda x: other_name == x[1], MyMainForm.dyname_win)    #判断来自对方的消息的窗口是否打开，如果打开则在上面添加消息，否则重新打开窗口添加消息
                for l in ld:
                    obj = l
                if obj[2] == 1:    #当窗口存在直接添加消息
                    if news[:8] == 'KEYINIT:':
                        frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                        self.generate_text_frame(frame_23, news[:20], other_name)
                        obj[0].verticalLayout_21.addWidget(frame_23)
                        pk_base64 = news[9:]
                        print('接收到公钥：' + pk_base64)
                        base64_decoded = base64.b64decode(pk_base64)
                        pk_type = ctypes.c_uint8 * CRYPTO_PUBLICKEYBYTES
                        pk = pk_type.from_buffer_copy(base64_decoded)
                        
                        # print(pk)
                        obj[0].ciphertext = (ctypes.c_uint8 * KYBER_INDCPA_BYTES)()
                        obj[0].shared_key = (ctypes.c_uint8 * KYBER_SYMBYTES)()
                        crypto_kem_enc(obj[0].ciphertext, obj[0].shared_key, pk)
                        
                        result = bytearray(obj[0].shared_key)  # 将ctypes数组转换为字节数组
                        obj[0].shared_key=result
                        base64_encoded = base64.b64encode(result).decode('utf-8')
                        print('生成共享密钥：' + base64_encoded)   
                        # print(1111)
                        key_bytes = bytearray(obj[0].ciphertext)
                        base64_encoded = base64.b64encode(key_bytes).decode('utf-8')
                        print('生成ciphertext:' + base64_encoded)
                        send_new = 'KEYINIT2:' + str(base64_encoded)
                        # print(2222)
                        frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                        obj[0].generate_text_frame_self(frame_27,send_new[:20], other_name)
                        # print(other_name)
                        obj[0].verticalLayout_21.addWidget(frame_27)        
                        new_dict = dict()
                        new_dict['personal_talk'] = other_name
                        # print(self.email)
                        new_dict['message'] = send_new
                        news = json.dumps(new_dict, ensure_ascii=False)
                        self.mythread.action(news)
                        
                        news = news[:20]
                    elif news[:8] == 'KEYINIT2':
                        frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                        self.generate_text_frame(frame_23, news[:20], other_name)
                        obj[0].verticalLayout_21.addWidget(frame_23)
                        
                        c_base64 = news[9:]
                        print('接收到ciphertext:' + c_base64)
                        base64_decoded = base64.b64decode(c_base64)
                        c_type = ctypes.c_uint8 * KYBER_INDCPA_BYTES
                        ciphertext = c_type.from_buffer_copy(base64_decoded)
                        out_shared_secret = (ctypes.c_uint8 * KYBER_SYMBYTES)()
                        crypto_kem_dec(out_shared_secret, ciphertext, obj[0].sk)
                        result = bytearray(out_shared_secret)  # 将ctypes数组转换为字节数组
                        obj[0].shared_key = result
                        base64_encoded = base64.b64encode(result).decode('utf-8')
                        print('生成共享密钥：' + base64_encoded)                        
                    elif news[:8] == 'ENCRYPT:':
                        news = news[9:]
                        frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                        self.generate_text_frame(frame_23, news, other_name)
                        obj[0].verticalLayout_21.addWidget(frame_23)
                        news = str(aes_decrypt(news.encode(), obj[0].shared_key).decode())
                        frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                        self.generate_text_frame(frame_23, news, other_name)
                        obj[0].verticalLayout_21.addWidget(frame_23)
                    else:
                        frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                        self.generate_text_frame(frame_23, news, other_name)
                        obj[0].verticalLayout_21.addWidget(frame_23)

                elif obj[2] == 0:   #当窗口不存在
                    obj[2] = 1    #打开窗口
                    obj[0].show()
                    if news[:8] == 'KEYINIT:':
                        frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                        self.generate_text_frame(frame_23, news[:20], other_name)
                        obj[0].verticalLayout_21.addWidget(frame_23)
                        pk_base64 = news[9:]
                        print('接收到公钥：' + pk_base64)
                        base64_decoded = base64.b64decode(pk_base64)
                        pk_type = ctypes.c_uint8 * CRYPTO_PUBLICKEYBYTES
                        pk = pk_type.from_buffer_copy(base64_decoded)
                        
                        # print(pk)
                        obj[0].ciphertext = (ctypes.c_uint8 * KYBER_INDCPA_BYTES)()
                        obj[0].shared_key = (ctypes.c_uint8 * KYBER_SYMBYTES)()
                        crypto_kem_enc(obj[0].ciphertext, obj[0].shared_key, pk)
                        
                        result = bytearray(obj[0].shared_key)  # 将ctypes数组转换为字节数组
                        base64_encoded = base64.b64encode(result).decode('utf-8')
                        print('生成共享密钥：' + base64_encoded)   
                        # print(1111)
                        key_bytes = bytearray(obj[0].ciphertext)
                        base64_encoded = base64.b64encode(key_bytes).decode('utf-8')
                        print('生成ciphertext:' + base64_encoded)
                        send_new = 'KEYINIT2:' + str(base64_encoded)
                        # print(2222)
                        frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                        obj[0].generate_text_frame_self(frame_27,send_new[:20], other_name)
                        # print(other_name)
                        obj[0].verticalLayout_21.addWidget(frame_27)        
                        new_dict = dict()
                        new_dict['personal_talk'] = other_name
                        # print(self.email)
                        new_dict['message'] = send_new
                        news = json.dumps(new_dict, ensure_ascii=False)
                        self.mythread.action(news)
                        
                        news = news[:20]
                    elif news[:8] == 'KEYINIT2':
                        frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                        self.generate_text_frame(frame_23, news[:20], other_name)
                        obj[0].verticalLayout_21.addWidget(frame_23)
                        
                        c_base64 = news[9:]
                        print('接收到ciphertext:' + c_base64)
                        base64_decoded = base64.b64decode(c_base64)
                        c_type = ctypes.c_uint8 * KYBER_INDCPA_BYTES
                        ciphertext = c_type.from_buffer_copy(base64_decoded)
                        out_shared_secret = (ctypes.c_uint8 * KYBER_SYMBYTES)()
                        crypto_kem_dec(out_shared_secret, ciphertext, obj[0].sk)
                        obj[0].shared_key = out_shared_secret
                        result = bytearray(out_shared_secret)  # 将ctypes数组转换为字节数组
                        base64_encoded = base64.b64encode(result).decode('utf-8')
                        print('生成共享密钥：' + base64_encoded)                         
                    else:
                        frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                        self.generate_text_frame(frame_23, news, other_name)
                        obj[0].verticalLayout_21.addWidget(frame_23)

            elif 'group_talk' in tmp:
                request_name = json.loads(tmp)
                send_email = request_name['group_talk']
                news = request_name['message']
                name = server_db.email2name(send_email).upper()
                name_first = name[0]
                img = "/src/images/字母/" + name_first + ".png"   
                
                frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                self.generate_text_frame(frame_23, news, send_email)
                self.verticalLayout_21.addWidget(frame_23)
            
            # elif 'personal_file' in tmp:
            #     request_name = json.loads(tmp)
            #     send_email = request_name['']

            else:
                self.textBrowser.append(tmp)
                with open('record.txt', 'a')as f:
                    f.write(tmp + '\n')

        except Exception as f:
            print(f)

    def select_files(self):
        box = QtWidgets.QMessageBox()
        box.warning(self,'Warning!',"请在私聊界面发送文件")
        
    def closed(self):
        client.exit()
        self.close()
        up_talk = filter(lambda x: 1 == x[2], MyMainForm.dyname_win)
        for i in up_talk:
            i[0].close()
            
    def change(self,item):    #按钮事件1（用户）
        try:
            box = QtWidgets.QMessageBox()
            word = item.email
            if word != self.email:    #不能点自己
                
                personal_record_cache = "./record_cache/" + self.email + "/" + word + '.txt'
                if not os.path.exists(personal_record_cache):
                    file = open(personal_record_cache, "a")
                    file.close()
                    
                list = filter(lambda x: word == x[1], MyMainForm.dyname_win)
                for li in list:
                    obj = li #obj为dyname_win的一项 (窗口, email, 0/1)
                if obj[2] == 1:
                    box.information(self, "温馨提示", " 别点了，您正在和他聊天呢!")
                else:
                    pp = Myrecvtalk(self.email, word)
                    obj[0] = pp
                    obj[0].show()
                    # with open('./line_people/other_name.txt', 'w')as d:
                    #     d.write(word)
                    obj[2] = 1

        except Exception as f:
            print(f)

    def text_changed(self):
        msg = self.textEdit_2.toPlainText()
        if '\n' in msg:
            msg = msg.replace('\n', '')
            self.textEdit_2.setText(msg)
            self.send_action()
            
    def send_action(self):
        try:
            req = self.textEdit_2.toPlainText()
            if req:
                
                frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                self.generate_text_frame_self(frame_27,req, self.email)
                self.verticalLayout_21.addWidget(frame_27)
                self.textEdit_2.clear() 
                package = dict()
                package["group"] = self.email
                package["message"] = req
                package = json.dumps(package, ensure_ascii=False)   
                self.mythread.action(package)
                
                local_time = time.localtime()
                now_time = '%s/%s/%s %s:%s:%s' % (local_time[:6])
                req = now_time + ':' + self.email + ':' + req
                
                with open('./record_cache/record.txt', 'a', encoding='utf-8')as h:
                    h.write(req + '\n')
        except Exception as e:
            print(e)

    def generate_text_frame(self, frame_23, message, email):
        frame_23.setMinimumSize(QtCore.QSize(0, 50))
        frame_23.setStyleSheet("")
        frame_23.setFrameShape(QtWidgets.QFrame.StyledPanel)
        frame_23.setFrameShadow(QtWidgets.QFrame.Raised)
        frame_23.setObjectName("frame_23")
        horizontalLayout_28 = QtWidgets.QHBoxLayout(frame_23)
        horizontalLayout_28.setContentsMargins(0, 0, 0, 0)
        horizontalLayout_28.setSpacing(12)
        horizontalLayout_28.setObjectName("horizontalLayout_28")
        frame_24 = QtWidgets.QFrame(frame_23)
        frame_24.setMinimumSize(QtCore.QSize(32, 32))
        
        
        name = server_db.email2name(email).upper()
        name_first = name[0]
        img = "image: url(:/png/images/字母/" + name_first +".png);"
        
        frame_24.setStyleSheet(img)
        frame_24.setFrameShape(QtWidgets.QFrame.NoFrame)
        frame_24.setFrameShadow(QtWidgets.QFrame.Raised)
        frame_24.setObjectName("frame_24")
        horizontalLayout_28.addWidget(frame_24)
        plainTextEdit = QtWidgets.QPlainTextEdit(frame_23)
        plainTextEdit.setAcceptDrops(False)
        plainTextEdit.setStyleSheet("text-align: right;\n"
"border-radius: 20px;\n"
"background-color: rgb(255, 255, 255);\n"
"padding:10px;")
        plainTextEdit.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        plainTextEdit.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        plainTextEdit.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustIgnored)
        plainTextEdit.setTabChangesFocus(False)
        plainTextEdit.setDocumentTitle("")
        plainTextEdit.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
        plainTextEdit.setReadOnly(True)
        plainTextEdit.setOverwriteMode(False)
        plainTextEdit.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        plainTextEdit.setBackgroundVisible(False)
        plainTextEdit.setCenterOnScroll(False)
        plainTextEdit.setObjectName("plainTextEdit")
        plainTextEdit.setPlainText(message)
        
        f = QFont()
        f.setPointSize(14)
        f.setFamily("Agency FB")
        plainTextEdit.setFont(f)
        
        horizontalLayout_28.addWidget(plainTextEdit)
        horizontalLayout_28.setStretch(0, 1)
        horizontalLayout_28.setStretch(1, 10)
    
    def generate_text_frame_self(self, frame_27, message, email):
        frame_27.setMinimumSize(QtCore.QSize(0, 50))
        frame_27.setFrameShape(QtWidgets.QFrame.StyledPanel)
        frame_27.setFrameShadow(QtWidgets.QFrame.Raised)
        frame_27.setObjectName("frame_27")
        horizontalLayout_30 = QtWidgets.QHBoxLayout(frame_27)
        horizontalLayout_30.setContentsMargins(0, 0, 0, 0)
        horizontalLayout_30.setSpacing(12)
        horizontalLayout_30.setObjectName("horizontalLayout_30")
        plainTextEdit_3 = QtWidgets.QPlainTextEdit(frame_27)
        plainTextEdit_3.setAcceptDrops(False)
        plainTextEdit_3.setLayoutDirection(QtCore.Qt.LeftToRight)
        plainTextEdit_3.setStyleSheet("text-align: right;\n"
"border-radius: 20px;\n"
"background-color: rgb(255, 255, 255);\n"
"padding:10px;")
        plainTextEdit_3.setFrameShape(QtWidgets.QFrame.NoFrame)
        plainTextEdit_3.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        plainTextEdit_3.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        plainTextEdit_3.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
        plainTextEdit_3.setReadOnly(True)
        plainTextEdit_3.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        plainTextEdit_3.setObjectName("plainTextEdit_3")
        plainTextEdit_3.setPlainText(message)
        horizontalLayout_30.addWidget(plainTextEdit_3)
        frame_28 = QtWidgets.QFrame(frame_27)
        frame_28.setMinimumSize(QtCore.QSize(32, 0))
        
        name = server_db.email2name(email).upper()
        name_first = self.name[0]
        img = "image: url(:/png/images/字母/" + name_first +".png);"
        
        f = QFont()
        f.setPointSize(14)
        f.setFamily("Agency FB")
        plainTextEdit_3.setFont(f)
        
        frame_28.setStyleSheet(img)
        frame_28.setFrameShape(QtWidgets.QFrame.NoFrame)
        frame_28.setFrameShadow(QtWidgets.QFrame.Raised)
        frame_28.setObjectName("frame_28")
        horizontalLayout_30.addWidget(frame_28)
        horizontalLayout_30.setStretch(0, 10)
        horizontalLayout_30.setStretch(1, 1)
            
    def notice_small(self):
        self.frame.setMaximumSize(16777, 16777)
        self.frame_2.setMaximumSize(0, 0)

    def notice_big(self):
        self.frame.setMaximumSize(0, 0)
        self.frame_2.setMaximumSize(16777, 16777)

    def widget_animation_start(self):
        if self.animation_event.is_set():
            return
        else:
            if self.widget_3.maximumWidth() == 0:
                self.widget_style_right(self.pushButton_2)
                self.animation_event.set()
                widget = QPropertyAnimation(self.widget_3, b"maximumWidth", self)
                widget.setStartValue(0)
                widget.setEndValue(200)
                widget.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
                widget.setDuration(400)
                widget.finished.connect(self.widget_animation_start_Signal)
                widget.start()
            else:
                self.widget_style_left(self.pushButton_2)
                self.animation_event.set()
                widget = QPropertyAnimation(self.widget_3, b"maximumWidth", self)
                widget.setStartValue(200)
                widget.setEndValue(0)
                widget.setDuration(400)
                widget.finished.connect(self.widget_animation_start_Signal)
                widget.start()

    def widget_animation_start_Signal(self):
        self.animation_event.clear()
        print(self.widget_3.maximumWidth())

    def float_animation_start(self):
        """主页"""
        if self.animation_event.is_set():
            return
        else:
            self.animation_event.set()
            if self.float_state_event.is_set():
                self.notice_small()
                notice = QPropertyAnimation(self, b"geometry", self)
                notice.setStartValue(
                    QRect(QDesktopWidget().screenGeometry().width() + self.float_width, self.float_y, self.float_width,
                          self.float_height))
                notice.setEndValue(
                    QRect(QDesktopWidget().screenGeometry().width() - self.float_width - self.float_right_x,
                          self.float_y, self.float_width, self.float_height))
                notice.setDuration(800)
                notice.finished.connect(self.float_animation_start_Signal)
                notice.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
                notice.start()

                notice = QPropertyAnimation(self, b"windowOpacity", self)
                notice.setStartValue(0)
                notice.setEndValue(1)
                notice.setDuration(200)
                notice.start()
            else:
                self.notice_big()
                notice = QPropertyAnimation(self, b"geometry", self)
                notice.setStartValue(QRect(self.x(), self.y(), 0, 0))
                notice.setEndValue(QRect(self.x(), self.y(), self.fixed_width, self.fixed_height))
                notice.setDuration(400)
                notice.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
                notice.finished.connect(self.float_animation_start_Signal)
                notice.start()

                notice = QPropertyAnimation(self, b"windowOpacity", self)
                notice.setStartValue(0)
                notice.setEndValue(1)
                notice.setDuration(200)
                notice.start()

    def float_animation_start_Signal(self):
        self.animation_event.clear()

    def float_animation_exit(self):
        if self.animation_event.is_set():
            return
        else:
            self.animation_event.set()
            if self.float_state_event.is_set():
                notice = QPropertyAnimation(self, b"geometry", self)
                notice.setStartValue(QRect(self.x(), self.y(), self.float_width, self.float_height))
                notice.setEndValue(
                    QRect(self.x() + self.float_width + 24, self.y(), self.float_width, self.float_height))
                notice.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
                notice.setDuration(800)
                notice.finished.connect(self.float_animation_exit_Signal)
                notice.start()
            else:
                notice = QPropertyAnimation(self, b"windowOpacity", self)
                notice.setStartValue(1)
                notice.setEndValue(0)
                notice.setDuration(800)
                notice.finished.connect(self.float_animation_exit_Signal)
                notice.start()

    def float_animation_exit_Signal(self):
        self.animation_event.clear()
        exit_package = dict()
        exit_package["login"] = 0
        exit_package["args"] = 'exit'
        exit_package = json.dumps(exit_package)
        self.mythread.action(exit_package)
        up_talk = filter(lambda x: 1 == x[2], MyMainForm.dyname_win)
        for i in up_talk:
            i[0].close()
        if self.record_win != None:
            self.record_win.close()
        self.close()

    def float_recovery_animation(self):
        """复原"""
        if self.animation_event.is_set():
            return
        else:
            self.notice_small()
            self.animation_event.set()
            notice = QPropertyAnimation(self, b"geometry", self)
            notice.setStartValue(QRect(self.x(), self.y(), self.width(), self.height()))
            notice.setEndValue(
                QRect(QDesktopWidget().screenGeometry().width() - self.float_width - self.float_right_x, self.float_y,
                      self.float_width, self.float_height))
            notice.setDuration(800)
            notice.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
            notice.finished.connect(self.animation_event.clear)
            notice.start()

    def float_deformation_animation(self):
        """变形"""
        if self.animation_event.is_set():
            return
        else:
            self.notice_big()
            self.animation_event.set()
            notice = QPropertyAnimation(self, b"geometry", self)
            notice.setStartValue(QRect(self.x(), self.y(), self.float_width, self.float_height))
            notice.setEndValue(QRect(self.x(), self.y(), self.fixed_width, self.fixed_height))
            notice.setDuration(400)
            notice.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
            notice.finished.connect(self.animation_event.clear)
            notice.start()

    def mouseReleaseEvent(self, event):
        if self.animation_event.is_set():
            return
        else:
            if self.float_state_event.is_set():
                if self.x() > QDesktopWidget().screenGeometry().width() / 5 * 4:
                    if self.animation_event.is_set():
                        return
                    self.float_recovery_animation()
                    self.float_state_event.set()
                else:
                    if self.animation_event.is_set():
                        return
                    self.float_deformation_animation()
                    self.float_state_event.clear()
            else:
                if self.x() + self.width() > QDesktopWidget().screenGeometry().width() / 10 * 9:
                    if self.animation_event.is_set():
                        return
                    self.float_recovery_animation()
                    self.float_state_event.set()

            self.start_x = None
            self.start_y = None

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            super(MyMainForm, self).mousePressEvent(event)
            self.start_x = event.x()
            self.start_y = event.y()

    def mouseMoveEvent(self, event):
        if self.animation_event.is_set():
            return
        else:
            try:
                super(MyMainForm, self).mouseMoveEvent(event)
                dis_x = event.x() - self.start_x
                dis_y = event.y() - self.start_y
                self.move(self.x() + dis_x, self.y() + dis_y)
            except:
                pass

    @staticmethod
    def widget_style_left(widget):
        style = """QPushButton{
            margin-right:3px;
            margin-bottom:0px;
            color: rgb(255, 255, 255);
            image: url(:/svg/images/svg/double-left.svg);
            border:1px outset rgb(255, 255, 255);
            border-radius:8px;
        }
        QPushButton:hover {
        
        border:2px outset rgba(36, 36, 36,0);
        }
        QPushButton:pressed {
        
        border:4px outset rgba(36, 36, 36,0);
        }"""
        widget.setStyleSheet(style)

    @staticmethod
    def widget_style_right(widget):
        style = """QPushButton{
            margin-right:3px;
            margin-bottom:0px;
            color: rgb(255, 255, 255);
            image: url(:/svg/images/svg/double-right.svg);
            border:1px outset rgb(255, 255, 255);
            border-radius:8px;
        }
        QPushButton:hover {

        border:2px outset rgba(36, 36, 36,0);
        }
        QPushButton:pressed {

        border:4px outset rgba(36, 36, 36,0);
        }"""
        widget.setStyleSheet(style)
        
class Myexp(QtWidgets.QMainWindow,Ui_exp):
    def __init__(self, x, y, textedit):
        super().__init__()    
        self.setupUi(self)
        self.start_x = x
        self.start_y = y
        self.textedit = textedit
        
        self.move(x, y)
        
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.setWindowFlags(Qt.FramelessWindowHint)  # 设置窗口标志：隐藏窗口边框
        
        self.pushButton_1.clicked.connect(self.exp1)
        self.pushButton_2.clicked.connect(self.exp2)
        self.pushButton_3.clicked.connect(self.exp3)
        self.pushButton_4.clicked.connect(self.exp4)
        
        self.pushButton_5.clicked.connect(self.exp5)
        self.pushButton_6.clicked.connect(self.exp6)
        self.pushButton_7.clicked.connect(self.exp7)
        self.pushButton_8.clicked.connect(self.exp8)
        
        self.pushButton_9.clicked.connect(self.exp9)
        self.pushButton_10.clicked.connect(self.exp10)
        self.pushButton_11.clicked.connect(self.exp11)
        self.pushButton_12.clicked.connect(self.exp12)
        
        self.pushButton_13.clicked.connect(self.exp13)
        self.pushButton_14.clicked.connect(self.exp14)
        self.pushButton_15.clicked.connect(self.exp15)
        self.pushButton_16.clicked.connect(self.exp16)
    
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.m_flag = True
            self.m_Position = event.globalPos() - self.pos()  # 获取鼠标相对窗口的位置
            event.accept()
            self.setCursor(QCursor(Qt.OpenHandCursor))  # 更改鼠标图标

    def mouseMoveEvent(self, QMouseEvent):
        self.m_flag = True
        if Qt.LeftButton and self.m_flag:
            self.move(QMouseEvent.globalPos() - self.m_Position)  # 更改窗口位置
            QMouseEvent.accept()

    def mouseReleaseEvent(self, QMouseEvent):
        self.m_flag = False
        self.setCursor(QCursor(Qt.ArrowCursor))
    
    def exp1(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("😙")
        self.close()
        return
    def exp2(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("🤯")
        self.close()
        return
    def exp3(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("😅")
        self.close()
        return
    def exp4(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("😮")
        self.close()
        return
    
    def exp5(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("😒")
        self.close()
        return
    def exp6(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("😚")
        self.close()
        return
    def exp7(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("😉")
        self.close()
        return
    def exp8(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("😡")
        self.close()
        return 

    def exp9(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("😳")
        self.close()
        return
    def exp10(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("😰")
        self.close()
        return
    def exp11(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("🙁")
        self.close()
        return
    def exp12(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("🙇")
        self.close()
        return

    def exp13(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("😏")
        self.close()
        return
    def exp14(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("😟")
        self.close()
        return
    def exp15(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("😀")
        self.close()
        return
    def exp16(self):
        cursor = self.textedit.textCursor()
        cursor.insertText("😓")
        self.close()
        return               

class Myrecord(QMainWindow, Ui_record):
    def __init__(self, send_email, recv_email):
        super().__init__()
        self.setupUi(self)
        
        self.recv_email = recv_email
        self.send_email = send_email
        
        self.recv_name = server_db.email2name(recv_email)
        self.NAME = server_db.email2name(recv_email).upper()
        self.name_first = self.NAME[0]
        if recv_email != '@':
            img = "image: url(:/png/images/字母/" + self.name_first +".png);"
            self.record_path = './record_cache/' + self.send_email + '/' + self.recv_email + '.txt'
        else:
            img = "image: url(:/png/images/group.png);"
            self.record_path = './record_cache/record.txt'
            
        self.widget.setStyleSheet(img)
        self.label_23.setText(self.recv_name + "  record")
        
        self.start_x = None
        self.start_y = None
        self.fixed_width = 710
        self.fixed_height = 569
        self.float_width = 357
        self.float_height = 100
        self.float_right_x = 14  # 右侧距离
        self.float_y = 700  # Y距离
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.setWindowFlags(Qt.FramelessWindowHint)  # 设置窗口标志：隐藏窗口边框
        self.animation_event = threading.Event()  # 动画信号
        self.float_state_event = threading.Event()  # 状态信号
        self.widget_3.setMaximumWidth(0)
        self.frame_2.setMaximumSize(0, 0)
        self.setGeometry(QRect(0, 0, 357, 75))
        #self.pushButton_2.clicked.connect(self.widget_animation_start)
        self.pushButton.clicked.connect(self.float_animation_exit)
        #self.pushButton_5.clicked.connect(self.exp_control)
        self.float_animation_start()
        
        self.show_record()
    
    def show_record(self):
        file = open(self.record_path, "r", encoding='utf-8')
        for line in file.readlines():
            curline = line.strip().split(':')
            stime = curline[0] +':'+ curline [1] +':'+ curline[2]
            send = curline[3]
            msg = curline[4]
            
            
            send_new = stime +'  '+ msg
            if send == self.send_email:
                frame_27 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                self.generate_text_frame_self(frame_27,send_new, send)
                self.verticalLayout_21.addWidget(frame_27)
            elif send == self.recv_email:
                frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                self.generate_text_frame(frame_23, send_new, send)
                self.verticalLayout_21.addWidget(frame_23)
            elif self.send_email == '@' and self.recv_email == '@':
                frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents_7)
                self.generate_text_frame(frame_23, send_new, send)
                self.verticalLayout_21.addWidget(frame_23)
        file.close()
                                  
    def notice_small(self):
        self.frame.setMaximumSize(16777, 16777)
        self.frame_2.setMaximumSize(0, 0)

    def notice_big(self):
        self.frame.setMaximumSize(0, 0)
        self.frame_2.setMaximumSize(16777, 16777)

    def widget_animation_start(self):
        if self.animation_event.is_set():
            return
        else:
            if self.widget_3.maximumWidth() == 0:
                self.widget_style_right(self.pushButton_2)
                self.animation_event.set()
                widget = QPropertyAnimation(self.widget_3, b"maximumWidth", self)
                widget.setStartValue(0)
                widget.setEndValue(200)
                widget.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
                widget.setDuration(400)
                widget.finished.connect(self.widget_animation_start_Signal)
                widget.start()
            else:
                self.widget_style_left(self.pushButton_2)
                self.animation_event.set()
                widget = QPropertyAnimation(self.widget_3, b"maximumWidth", self)
                widget.setStartValue(200)
                widget.setEndValue(0)
                widget.setDuration(400)
                widget.finished.connect(self.widget_animation_start_Signal)
                widget.start()

    def widget_animation_start_Signal(self):
        self.animation_event.clear()
        print(self.widget_3.maximumWidth())

    def float_animation_start(self):
        """主页"""
        if self.animation_event.is_set():
            return
        else:
            self.animation_event.set()
            if self.float_state_event.is_set():
                self.notice_small()
                notice = QPropertyAnimation(self, b"geometry", self)
                notice.setStartValue(
                    QRect(QDesktopWidget().screenGeometry().width() + self.float_width, self.float_y, self.float_width,
                          self.float_height))
                notice.setEndValue(
                    QRect(QDesktopWidget().screenGeometry().width() - self.float_width - self.float_right_x,
                          self.float_y, self.float_width, self.float_height))
                notice.setDuration(800)
                notice.finished.connect(self.float_animation_start_Signal)
                notice.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
                notice.start()

                notice = QPropertyAnimation(self, b"windowOpacity", self)
                notice.setStartValue(0)
                notice.setEndValue(1)
                notice.setDuration(200)
                notice.start()
            else:
                self.notice_big()
                notice = QPropertyAnimation(self, b"geometry", self)
                notice.setStartValue(QRect(self.x(), self.y(), 0, 0))
                notice.setEndValue(QRect(self.x(), self.y(), self.fixed_width, self.fixed_height))
                notice.setDuration(400)
                notice.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
                notice.finished.connect(self.float_animation_start_Signal)
                notice.start()

                notice = QPropertyAnimation(self, b"windowOpacity", self)
                notice.setStartValue(0)
                notice.setEndValue(1)
                notice.setDuration(200)
                notice.start()

    def float_animation_start_Signal(self):
        self.animation_event.clear()

    def float_animation_exit(self):
        if self.animation_event.is_set():
            return
        else:
            self.animation_event.set()
            if self.float_state_event.is_set():
                notice = QPropertyAnimation(self, b"geometry", self)
                notice.setStartValue(QRect(self.x(), self.y(), self.float_width, self.float_height))
                notice.setEndValue(
                    QRect(self.x() + self.float_width + 24, self.y(), self.float_width, self.float_height))
                notice.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
                notice.setDuration(800)
                notice.finished.connect(self.float_animation_exit_Signal)
                notice.start()
            else:
                notice = QPropertyAnimation(self, b"windowOpacity", self)
                notice.setStartValue(1)
                notice.setEndValue(0)
                notice.setDuration(800)
                notice.finished.connect(self.float_animation_exit_Signal)
                notice.start()

    def float_animation_exit_Signal(self):
        self.animation_event.clear()
        self.close()

    def float_recovery_animation(self):
        """复原"""
        if self.animation_event.is_set():
            return
        else:
            self.notice_small()
            self.animation_event.set()
            notice = QPropertyAnimation(self, b"geometry", self)
            notice.setStartValue(QRect(self.x(), self.y(), self.width(), self.height()))
            notice.setEndValue(
                QRect(QDesktopWidget().screenGeometry().width() - self.float_width - self.float_right_x, self.float_y,
                      self.float_width, self.float_height))
            notice.setDuration(800)
            notice.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
            notice.finished.connect(self.animation_event.clear)
            notice.start()

    def float_deformation_animation(self):
        """变形"""
        if self.animation_event.is_set():
            return
        else:
            self.notice_big()
            self.animation_event.set()
            notice = QPropertyAnimation(self, b"geometry", self)
            notice.setStartValue(QRect(self.x(), self.y(), self.float_width, self.float_height))
            notice.setEndValue(QRect(self.x(), self.y(), self.fixed_width, self.fixed_height))
            notice.setDuration(400)
            notice.setEasingCurve(QEasingCurve.OutElastic)  # 弹性动画
            notice.finished.connect(self.animation_event.clear)
            notice.start()

    def mouseReleaseEvent(self, event):
        if self.animation_event.is_set():
            return
        else:
            if self.float_state_event.is_set():
                if self.x() > QDesktopWidget().screenGeometry().width() / 5 * 4:
                    if self.animation_event.is_set():
                        return
                    self.float_recovery_animation()
                    self.float_state_event.set()
                else:
                    if self.animation_event.is_set():
                        return
                    self.float_deformation_animation()
                    self.float_state_event.clear()
            else:
                if self.x() + self.width() > QDesktopWidget().screenGeometry().width() / 10 * 9:
                    if self.animation_event.is_set():
                        return
                    self.float_recovery_animation()
                    self.float_state_event.set()

            self.start_x = None
            self.start_y = None

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            #super(Ui_recv_win, self).mousePressEvent(event)
            self.start_x = event.x()
            self.start_y = event.y()

    def mouseMoveEvent(self, event): 
        if self.animation_event.is_set():
            return
        else:
            try:
                #super(Ui_recv_win, self).mouseMoveEvent(event)
                dis_x = event.x() - self.start_x
                dis_y = event.y() - self.start_y
                self.move(self.x() + dis_x, self.y() + dis_y)
            except:
                pass

    @staticmethod
    def widget_style_left(widget):
        style = """QPushButton{
            margin-right:3px;
            margin-bottom:0px;
            color: rgb(255, 255, 255);
            image: url(:/svg/images/svg/double-left.svg);
            border:1px outset rgb(255, 255, 255);
            border-radius:8px;
        }
        QPushButton:hover {
        
        border:2px outset rgba(36, 36, 36,0);
        }
        QPushButton:pressed {
        
        border:4px outset rgba(36, 36, 36,0);
        }"""
        widget.setStyleSheet(style)

    @staticmethod
    def widget_style_right(widget):
        style = """QPushButton{
            margin-right:3px;
            margin-bottom:0px;
            color: rgb(255, 255, 255);
            image: url(:/svg/images/svg/double-right.svg);
            border:1px outset rgb(255, 255, 255);
            border-radius:8px;
        }
        QPushButton:hover {

        border:2px outset rgba(36, 36, 36,0);
        }
        QPushButton:pressed {

        border:4px outset rgba(36, 36, 36,0);
        }"""
        widget.setStyleSheet(style)        
    
    def generate_text_frame(self, frame_23, message, email):
        frame_23.setMinimumSize(QtCore.QSize(0, 50))
        frame_23.setStyleSheet("")
        frame_23.setFrameShape(QtWidgets.QFrame.StyledPanel)
        frame_23.setFrameShadow(QtWidgets.QFrame.Raised)
        frame_23.setObjectName("frame_23")
        horizontalLayout_28 = QtWidgets.QHBoxLayout(frame_23)
        horizontalLayout_28.setContentsMargins(0, 0, 0, 0)
        horizontalLayout_28.setSpacing(12)
        horizontalLayout_28.setObjectName("horizontalLayout_28")
        frame_24 = QtWidgets.QFrame(frame_23)
        frame_24.setMinimumSize(QtCore.QSize(32, 32))
        
        
        name = server_db.email2name(email)
        name_first = name[0]
        img = "image: url(:/png/images/字母/" + name_first +".png);"
        
        frame_24.setStyleSheet(img)
        frame_24.setFrameShape(QtWidgets.QFrame.NoFrame)
        frame_24.setFrameShadow(QtWidgets.QFrame.Raised)
        frame_24.setObjectName("frame_24")
        horizontalLayout_28.addWidget(frame_24)
        plainTextEdit = QtWidgets.QPlainTextEdit(frame_23)
        plainTextEdit.setAcceptDrops(False)
        plainTextEdit.setStyleSheet("text-align: right;\n"
"border-radius: 20px;\n"
"background-color: rgb(255, 255, 255);\n"
"padding:10px;")
        plainTextEdit.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        plainTextEdit.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        plainTextEdit.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustIgnored)
        plainTextEdit.setTabChangesFocus(False)
        plainTextEdit.setDocumentTitle("")
        plainTextEdit.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
        plainTextEdit.setReadOnly(True)
        plainTextEdit.setOverwriteMode(False)
        plainTextEdit.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        plainTextEdit.setBackgroundVisible(False)
        plainTextEdit.setCenterOnScroll(False)
        plainTextEdit.setObjectName("plainTextEdit")
        plainTextEdit.setPlainText(message)
        
        f = QFont()
        f.setPointSize(11)
        f.setFamily("Agency FB")
        plainTextEdit.setFont(f)
        
        horizontalLayout_28.addWidget(plainTextEdit)
        horizontalLayout_28.setStretch(0, 1)
        horizontalLayout_28.setStretch(1, 10)
    
    def generate_text_frame_self(self, frame_27, message, email):
        frame_27.setMinimumSize(QtCore.QSize(0, 50))
        frame_27.setFrameShape(QtWidgets.QFrame.StyledPanel)
        frame_27.setFrameShadow(QtWidgets.QFrame.Raised)
        frame_27.setObjectName("frame_27")
        horizontalLayout_30 = QtWidgets.QHBoxLayout(frame_27)
        horizontalLayout_30.setContentsMargins(0, 0, 0, 0)
        horizontalLayout_30.setSpacing(12)
        horizontalLayout_30.setObjectName("horizontalLayout_30")
        plainTextEdit_3 = QtWidgets.QPlainTextEdit(frame_27)
        plainTextEdit_3.setAcceptDrops(False)
        plainTextEdit_3.setLayoutDirection(QtCore.Qt.LeftToRight)
        plainTextEdit_3.setStyleSheet("text-align: right;\n"
"border-radius: 20px;\n"
"background-color: rgb(255, 255, 255);\n"
"padding:10px;")
        plainTextEdit_3.setFrameShape(QtWidgets.QFrame.NoFrame)
        plainTextEdit_3.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        plainTextEdit_3.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        plainTextEdit_3.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
        plainTextEdit_3.setReadOnly(True)
        plainTextEdit_3.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        plainTextEdit_3.setObjectName("plainTextEdit_3")
        plainTextEdit_3.setPlainText(message)
        horizontalLayout_30.addWidget(plainTextEdit_3)
        frame_28 = QtWidgets.QFrame(frame_27)
        frame_28.setMinimumSize(QtCore.QSize(32, 0))
        
        name = server_db.email2name(email)
        name_first =name[0]
        img = "image: url(:/png/images/字母/" + name_first +".png);"
        
        f = QFont()
        f.setPointSize(11)
        f.setFamily("Agency FB")
        plainTextEdit_3.setFont(f)
        
        frame_28.setStyleSheet(img)
        frame_28.setFrameShape(QtWidgets.QFrame.NoFrame)
        frame_28.setFrameShadow(QtWidgets.QFrame.Raised)
        frame_28.setObjectName("frame_28")
        horizontalLayout_30.addWidget(frame_28)
        horizontalLayout_30.setStretch(0, 10)
        horizontalLayout_30.setStretch(1, 1)
       

class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return str(obj, encoding='utf-8')        
        
        
        
        
        
        
        
        
        
        
        
    
        