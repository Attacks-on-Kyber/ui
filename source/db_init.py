import sqlite3
from sqlite3 import Error

def db_connect():
    try:
        con = sqlite3.connect('server.db')
        return con
    except Error:
        print(Error)

def db_create_table():
    try:
        con = sqlite3.connect('server.db')
    except Error:
        print(Error)
    cur = con.cursor()
    cur.execute("CREATE TABLE User(Email text PRIMARY KEY, user_name text, password text)")
    con.commit()

def db_insert():
    try:
        con = sqlite3.connect('server.db')
    except Error:
        print(Error)
    cur = con.cursor()
    cur.execute("INSERT INTO User VALUES('123456789@qq.com', 'Alice', '123456')")
    con.commit()

def db_insert2(entities):
    try:
        con = sqlite3.connect('server.db')
    except Error:
        print(Error)
    cur = con.cursor()
    cur.execute("INSERT INTO User(Email, user_name, password) VALUES(?, ?, ?)", entities)
    con.commit()

# entities = ('987654321@qq.com', 'Bob', '123456')

# db_insert2(entities)

def db_update():
    try:
        con = sqlite3.connect('server.db')
    except Error:
        print(Error)
    cur = con.cursor()
    cur.execute("UPDATE User SET user_name='Coral' where Email = '987654321@qq.com'")
    con.commit()

#db_update()

def db_fetch():
    try:
        con = sqlite3.connect('server.db')
    except Error:
        print(Error)
    cur = con.cursor()
    cur.execute("SELECT * FROM User")
    rows = cur.fetchall()
    for row in rows:
        print(row)
    
db_create_table()
db_insert()
entities = ('987654321@qq.com', 'Bob', '123456')
db_insert2(entities)

    