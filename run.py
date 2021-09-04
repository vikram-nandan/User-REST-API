from flask import Flask, request, Response
import json
import database_service
from custom_auth import custom_auth

app = Flask(__name__)
database_service.create_usertable()
database_service.create_registertable()

cauth = custom_auth()
cauth.dbname = "userinfo.db"
cauth.secret_key = b'48YTkPjPSOeZFK4JNipNfDfFoH0mn6YVmv0GiDEAris='


@app.route("/")
def index():
    """
    :return: "Application Connection Status"
    """
    return "Application Connection Success"


@app.route("/register", methods=["POST"])
def register():
    """
    :return: User Registration Status
    Takes user and password from requests and adds it to the register table
    password is encrypted using cryptography
    returns the status after insertion
    """
    try:
        if request.method == "POST":
            json_request = request.json
            user = json_request.get("user")
            password = json_request.get("password")
            if user is None or password is None:
                return {"message": "user or password cannot be None"}
            database_service.register_user(user, password)
            response_dict = {"message": "inserted successfully"}
            response = Response(response=json.dumps(response_dict), mimetype="application/json")
            response.headers["Content-Type"] = "application/json; charset=utf-8"
            return response
    except Exception as err:
        response_dict = {"message": str(err)}
        response = Response(response=json.dumps(response_dict), mimetype="application/json")
        response.headers["Content-Type"] = "application/json; charset=utf-8"
        return response


@app.route("/insert", methods=["POST"])
@cauth.user_authentication()
@cauth.role_authorization(allowed_users=["admin"])
def insert():
    """
    :return: User Insertion Status
    Decorated with custom user authentication and role authorization
    Allows only the admin user to insert new records
    Takes name, email and telephone from request and adds it to the user table
    returns the status after insertion
    """
    try:
        if request.method == "POST":
            json_request = request.json
            name = json_request.get("name")
            email = json_request.get("email")
            telephone = json_request.get("telephone")
            database_service.insert_userdetails(name, email, telephone)
            response_dict = {"message": "inserted successfully"}
            response = Response(response=json.dumps(response_dict), mimetype="application/json")
            response.headers["Content-Type"] = "application/json; charset=utf-8"
            return response
    except Exception as err:
        response_dict = {"message": str(err)}
        response = Response(response=json.dumps(response_dict), mimetype="application/json")
        response.headers["Content-Type"] = "application/json; charset=utf-8"
        return response


@app.route("/update/<string:name>", methods=["PUT"])
@cauth.user_authentication()
@cauth.role_authorization(allowed_users=["admin"])
def update(name):
    """
    :param: name
    :return: User Update Status
    Decorated with custom user authentication and role authorization
    Allows only the admin user to update new records
    Takes name as key and updates email and telephone from request to the user table
    returns the status after update
    """
    try:
        if request.method == "PUT":
            json_request = request.json
            email = json_request.get("email")
            telephone = json_request.get("telephone")
            database_service.update_userdetails(name, email, telephone)
            response_dict = {"message": "updated successfully"}
            response = Response(response=json.dumps(response_dict), mimetype="application/json")
            response.headers["Content-Type"] = "application/json; charset=utf-8"
            return response
    except Exception as err:
        response_dict = {"message": str(err)}
        response = Response(response=json.dumps(response_dict), mimetype="application/json")
        response.headers["Content-Type"] = "application/json; charset=utf-8"
        return response


@app.route("/retrieve", methods=["GET"])
@cauth.user_authentication()
def retrieve():
    """
    :return: User Records
    Decorated with custom user authentication
    Allows only the registered user to access the records
    returns all records from the user table
    """
    try:
        if request.method == "GET":
            response_dict = database_service.retrieve_userdetails()
            response = Response(response=json.dumps(response_dict), mimetype="application/json")
            response.headers["Content-Type"] = "application/json; charset=utf-8"
            return response
    except Exception as err:
        response_dict = {"message": str(err)}
        response = Response(response=json.dumps(response_dict), mimetype="application/json")
        response.headers["Content-Type"] = "application/json; charset=utf-8"
        return response


@app.route("/retrieve/<string:name>", methods=["GET"])
@cauth.user_authentication()
def retrieve_user(name):
    """
    :param: name
    :return: User Record
    Decorated with custom user authentication
    Allows only the registered user to access the records
    Takes name as key and retrieves email and telephone from user table
    returns the name, email and telephone
    """
    try:
        if request.method == "GET":
            response_dict = database_service.retrieve_userdetails(name)
            response = Response(response=json.dumps(response_dict), mimetype="application/json")
            response.headers["Content-Type"] = "application/json; charset=utf-8"
            return response
    except Exception as err:
        response_dict = {"message": str(err)}
        response = Response(response=json.dumps(response_dict), mimetype="application/json")
        response.headers["Content-Type"] = "application/json; charset=utf-8"
        return response


if __name__ == "__main__":
    app.run()
