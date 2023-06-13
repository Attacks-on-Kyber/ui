import sqlite3
from sqlite3 import Error

def check_Email(email):
    '''
    校验邮箱是否存在
    :return:0 表示存在， 1表示不存在
    '''
    try:
        con = sqlite3.connect('server.db')
    except Error:
        print(Error)
    try:
            cur = con.cursor()
            cur.execute("select Email from User where Email = '{}'".format(email))
            rows = cur.fetchall()

    finally:
        con.close()

    if rows:
        return 0     #邮箱存在
    else:
        return 1     #邮箱不存在


def check_username(username):
    '''
    校验昵称是否存在
    :return: 0表示存在， 1表示不存在
    '''
    try:
        con = sqlite3.connect('server.db')
    except Error:
        print(Error)
    try:
            cur = con.cursor()
            cur.execute("select user_name from User where user_name = '{}'".format(username))
            rows = cur.fetchall()

    finally:
        con.close()

    if rows:
        return 0     #用户名存在
    else:
        return 1     #用户名不存在

#print(check_username('Alice'))

def check_password(email, password):
    '''
    验证密码是否正确
    :正确return 0; 错误返回return 1
    '''
    try:
        con = sqlite3.connect('server.db')
    except Error:
        print(Error)
    try:
        cur = con.cursor()
        cur.execute("select password from User where Email = '{}'".format(email))
        rows = cur.fetchall()

    finally:
        con.close()
    if rows[0][0] == password:
        return 0     #正确
    else:
        return 1     #错误

#print(check_password('987654321@qq.com', '123456'))

def modify_pd(email, password):
    '''
    根据邮箱修改密码
    '''
    try:
        con = sqlite3.connect('server.db')
    except Error:
        print(Error)
    try:
        cur = con.cursor()
        cur.execute("UPDATE User SET password='{}' where Email='{}'".format(password, email))
        con.commit()
    finally:
        con.close()
#modify_ps('987654321@qq.com', '654321')

def modify_name(email, name):
    '''
    根据邮箱修改昵称
    '''
    try:
        con = sqlite3.connect('server.db')
    except Error:
        print(Error)
    
    try:
        cur = con.cursor()
        cur.execute("UPDATE User SET user_name='{}' where Email='{}'".format(name, email))
        con.commit()
    finally:
        con.close()

#modify_name('987654321@qq.com', 'Kira') 

def add_user(email, username, password):
    '''
    添加一个用户
    '''
    try:
        con = sqlite3.connect('server.db')
    except Error:
        print(Error)
    
    try:
        cur = con.cursor()
        cur.execute("INSERT INTO User VALUES('{}', '{}','{}')".format(email, username, password))
        con.commit()
    finally:
        con.close()
#add_user('456789123@qq.com', 'Elieen', '123456')

def email2name(email):
    '''
    根据邮箱查找昵称
    :查找成功返回昵称,查找失败返回1
    '''
    try:
        con = sqlite3.connect('server.db')
    except Error:
        print(Error)
    
    try:
        cur = con.cursor()
        cur.execute("SELECT user_name FROM User where Email='{}'".format(email))
        rows = cur.fetchall()
        con.commit()
    finally:
        con.close()
    
    if rows[0][0]:
        return rows[0][0]     #正确
    else:
        return 1     #错误
#print(email2name('123456789@qq.com'))
    
    