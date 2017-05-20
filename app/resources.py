from flask import request, jsonify, g
from flask_restful import Resource
from flask_restful import fields, marshal, reqparse
from flask_httpauth import HTTPBasicAuth

from app.models import Bucketlists, Users

auth = HTTPBasicAuth()

def get_auth_token(expiration=600):
    token = g.user.generate_auth_token(expiration=expiration)
    return jsonify({ "token": token.decode("utf-8") })


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = Users.verify_auth_token(username_or_token)
    if user in ["expired", "invalid"]:
        user = None
    if not user:
        # try to authenticate with username/password
        user = Users.query.filter_by(user_name=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


class UserRegistrationAPI(Resource):
    """ creates new users """

    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)
        self.reqparse.add_argument("username", type=str, required=True,
                                   help="No user_name provided")
        self.reqparse.add_argument("password", type=str, required=True,
                                   help="No password provided")

        super(UserRegistrationAPI, self).__init__()

    def post(self):
        args = self.reqparse.parse_args()
        username = args["username"]
        password = args["password"]

        # check if user exists
        if Users.query.filter_by(user_name = username).first() is not None:
            return {"username": "Username already exists"}, 400

        user = Users(username, password)
        user.save()

        return {"id":user.id,
                "user_name":username,
                "date_registered":str(user.date_registered)
               }, 201


class UserLoginAPI(Resource):
    """ Enables log in for registered users """
    users = {}

    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)
        self.reqparse.add_argument("username_or_token", type=str, required=True,
                                   help="No username_or_token provided")
        self.reqparse.add_argument("password", type=str, help="Password has to be a string")
        super(UserLoginAPI, self).__init__()

    def post(self):

        args = self.reqparse.parse_args()
        username_or_token = args["username_or_token"]
        password = args["password"]

        if verify_password(username_or_token, password):
            user = g.user

            token = user.generate_auth_token(expiration=600)
            token = token.decode("utf-8")
            UserLoginAPI.users[user.id] = token

            response = {"id": user.id,
                        "username":user.user_name,
                        "message":"You have logged in successfully",
                        "token":token
                       }, 200
            return response

        return {"message":"Invalid username_or_token and/or password - Try again"}, 403


class UserLogOutAPI(Resource):
    """ Enables log out for users """
    decorators = [auth.login_required]

    def delete(self):
        user = g.user

        if UserLoginAPI.users.get(user.id, None) is not None:
            del UserLoginAPI.users[user.id]
        del user


class GetTokenAPI(Resource):
    """enables logged in user to refresh their expired token"""
    decorators = [auth.login_required]

    def get(self):
        user = g.user
        token = get_auth_token()
        UserLoginAPI.users[user.id] = token.data.decode("utf-8").split('"')[3]

        return token

class BucketListsAPI(Resource):
    """ creates new bucketlists and fetches existing bucketlists"""
    decorators = [auth.login_required]

    def __init__(self):

        self.reqparse = reqparse.RequestParser(bundle_errors=True)
        self.reqparse.add_argument("name", type=str, required=True,
                                   help="No bucketlist name provided")
        super(BucketListsAPI, self).__init__()

    def get(self):
        """gets all bucketlists belonging to user"""

        token = request.headers.get("token","")
        user = g.user

        # ensure token belongs to current user
        if token != UserLoginAPI.users.get(user.id, ""):
            return {"error": "Received token does not belong to you"}, 403

        token_auth = Users.verify_auth_token(token)

        if token_auth in ["expired", "invalid"]:
            if token_auth == "expired":
                return {"message": "Expired token, request for a new one"}, 403
            else:
                return {"message": "Invalid token"}, 403

        else:
            bucketlists = Bucketlists.get_all_for_user(user_id=user.id)
            results = []

            for bucketlist in bucketlists:
                obj = {
                    "id": bucketlist.id,
                    "name": bucketlist.name,
                    "date_created": bucketlist.date_created,
                    "created_by": user.id,
                    "date_modified": bucketlist.date_modified
                }
                results.append(obj)
            response = jsonify(results)
            response.status_code = 200
            return response





    def post(self):
        """
        creates new bucketlists
        """
        token = request.headers.get("token","")
        user = g.user
        # ensure token belongs to current user
        if token != UserLoginAPI.users.get(user.id, ""):
            return {"error": "Received token does not belong to you"}

        if Users.verify_auth_token(token):
            args = self.reqparse.parse_args()
            name = args["name"]

            if name:
                user_id = g.user.id
                bucketlist = Bucketlists(name, user_id)
                bucketlist.save()
                response = {
                    "id": bucketlist.id,
                    "name": bucketlist.name,
                    "date_created": str(bucketlist.date_created),
                    "date_modified": str(bucketlist.date_modified),
                    "created by": user_id
                }

                return response, 201
            return {"error": "No bucketlist name provided"}, 400

        return {"message": "Invalid token"}


class BucketListAPI(Resource):
    """Gets , updates or deletes single bucketlist"""
    decorators = [auth.login_required]
    def put(self):
        pass

    def get(self):
        pass

    def delete(self):
        pass



class BucketListItemAPI(Resource):
    """Updates or deletes a single bucketlist item"""

    decorators = [auth.login_required]

    def put(self):
        pass

    def delete(self):
        pass



class BucketListItemsAPI(Resource):
    """Create a new item in bucket list"""

    decorators = [auth.login_required]

    def post(self):
        pass
