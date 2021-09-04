from base64 import b64decode
from flask import request
import sqlite3
from cryptography.fernet import Fernet
from functools import wraps


class custom_auth(object):

    def __init__(self, header=None, secret_key=None, dbname=None):
        """
        :param: header, secret_key, dbname
        Intializes header, secret_key and dbname
        """
        self.header = header
        self.secret_key = secret_key
        self.dbname = dbname

    def get_auth(self):
        """
        Returns decoded username and password from the request Authorization header
        """
        header = 'Authorization'
        if header not in request.headers:
            return None
        value = request.headers[header].encode('utf-8')
        try:
            scheme, credentials = value.split(b' ', 1)
            username, password = b64decode(credentials).split(b':', 1)
        except (ValueError, TypeError):
            return None
        try:
            username = username.decode('utf-8')
            password = password.decode('utf-8')
        except UnicodeDecodeError:
            username = None
            password = None
        return {'username': username, 'password': password}

    def role_authorization(self, allowed_users=[]):
        """
        :param: allowed_users
        Checks if the user is a allowed_user
        """

        def role_auth_decorator(function):
            @wraps(function)
            def role_auth_wrapper(*args, **kwargs):
                auth = self.get_auth()
                username = auth['username']
                if username in allowed_users:
                    return function(*args, **kwargs)
                else:
                    raise Exception("Permission Denied")

            return role_auth_wrapper

        return role_auth_decorator

    def user_authentication(self):
        """
        Checks if the user's credential is alid
        """

        def user_auth_decorator(function):
            @wraps(function)
            def user_auth_wrapper(*args, **kwargs):
                auth = self.get_auth()
                username = auth['username']
                password = auth['password']
                secret_key = self.secret_key
                dbname = self.dbname
                fernet = Fernet(secret_key)
                with sqlite3.connect(dbname) as connection:
                    cursor = connection.cursor()
                    retrieve_query = """SELECT * FROM register WHERE user=?"""
                    cursor.execute(retrieve_query, [username])
                    encMessage = cursor.fetchone()[1]
                    connection.commit()
                encpassword = fernet.decrypt(encMessage).decode()
                if password == encpassword:
                    return function(*args, **kwargs)
                else:
                    raise Exception("Access Denied")

            return user_auth_wrapper

        return user_auth_decorator
