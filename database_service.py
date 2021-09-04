import sqlite3
from cryptography.fernet import Fernet

db_name = "userinfo.db"
key = b'48YTkPjPSOeZFK4JNipNfDfFoH0mn6YVmv0GiDEAris='
fernet = Fernet(key)


def create_registertable():
    """
    Creates register table with user TEXT PRIMARY KEY and password TEXT
    """
    try:
        with sqlite3.connect(db_name) as connection:
            cursor = connection.cursor()
            create_query = """
                    CREATE TABLE IF NOT EXISTS register
                    (
                    user TEXT PRIMARY KEY, 
                    password TEXT 
                    )
                    """
            cursor.execute(create_query)
            connection.commit()
    except Exception as err:
        return str(err)


def create_usertable():
    """
    Creates user table with name TEXT PRIMARY KEY, email TEXT and telephone TEXT
    """
    try:
        with sqlite3.connect(db_name) as connection:
            cursor = connection.cursor()
            create_query = """
                    CREATE TABLE IF NOT EXISTS user
                    (
                    name TEXT PRIMARY KEY, 
                    email TEXT, 
                    telephone TEXT
                    )
                    """
            cursor.execute(create_query)
            connection.commit()
    except Exception as err:
        return str(err)


def insert_userdetails(name, email, telephone):
    """
    :param: name, email, telephone
    Inserts name, email and telephone into user table
    """
    try:
        with sqlite3.connect(db_name) as connection:
            cursor = connection.cursor()
            insert_query = """
                    INSERT INTO user
                    (name, email, telephone)
                    VALUES
                    (?, ?, ?)    
                    """
            cursor.execute(insert_query, (name, email, telephone))
            connection.commit()
    except Exception as err:
        return str(err)


def update_userdetails(name, email, telephone):
    """
    :param: name, email, telephone
    Checks if the user is present in user table if not raises exception
    updates email and telephone based on user in user table
    """
    try:
        with sqlite3.connect(db_name) as connection:
            cursor = connection.cursor()

            checkuser_query = """SELECT * FROM user WHERE name=?"""
            cursor.execute(checkuser_query, [name])
            valid_user = cursor.fetchone()

            if valid_user is not None:
                update_query = """
                UPDATE user SET name = ?, email = ?, telephone = ?
                WHERE name = ? 
                """
                cursor.execute(update_query, (name, email, telephone, name))
                connection.commit()
            else:
                raise Exception("user does not exists")

    except Exception as err:
        return str(err)


def retrieve_userdetails(name=None):
    """
    :param: name
    Checks if the name is None in param
    If name is None, returns all records from user table
    If name is nor None, returns only the record for the param name from user table
    """
    try:
        with sqlite3.connect(db_name) as connection:
            cursor = connection.cursor()
            if name is None:
                retrieve_query = """SELECT * FROM user"""
                cursor.execute(retrieve_query)
            else:
                retrieve_query = """SELECT * FROM user WHERE name=?"""
                cursor.execute(retrieve_query, [name])
            data = cursor.fetchall()
            connection.commit()
            return data
    except Exception as err:
        return str(err)


def encrypt_password(password):
    """
    :param: password
    Encrypts the password using cryptography
    """
    try:
        encpassword = fernet.encrypt(password.encode())
        return encpassword
    except Exception as err:
        return str(err)


def register_user(user, password):
    """
    :param: user, password
    Inserts user and encrypted password into register table
    """
    try:
        with sqlite3.connect(db_name) as connection:
            cursor = connection.cursor()
            insert_query = """
                    INSERT INTO register
                    (user, password)
                    VALUES
                    (?, ?)    
                    """
            cursor.execute(insert_query, (user, encrypt_password(password)))
            connection.commit()
    except Exception as err:
        return str(err)
