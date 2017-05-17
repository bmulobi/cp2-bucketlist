from flask import request, jsonify, g
from flask_restful import Resource
from flask_restful import fields, marshal, reqparse
from flask_httpauth import HTTPBasicAuth

from app.models import Bucketlists, Users

auth = HTTPBasicAuth()

# response_fields = {
#     "id": fields.Integer,
#     "name": fields.String,
#
# "items": fields.Nested({
#
# "id": fields.Integer,
#
# "name
# ": fields.String,
#     "date_created": fields.DateTime,
#
# "date_modified": fields.DateTime,
#
# "done": fields.Boolean,
#     }),
#     "date_created": fields.DateTime,
#     "date_modified": fields.DateTime,
#     "created_by": fields.String,
# }


def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({ "token": token.decode("ascii") })


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = Users.verify_auth_token(username_or_token)
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

        # password = pwd_context.encrypt(password)

        if Users.query.filter_by(user_name = username).first() is not None: # existing user
            return {"username": "Username already exists"}

        user = Users(username, password)
        user.save()

        return {"id":user.id,
                "user_name":username,
                "date_registered":str(user.date_registered)
               }, 201


class UserLoginAPI(Resource):
    """ Enables log in for registered users """

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
            response = {"username":user.user_name,
                    "message":"You have logged in successfully",
                    "token":token.decode("ascii")
                    }, 200
            return response



        return {"message":"Invalid username_or_token and/or password - Try again"}, 403


class GetTokenAPI(Resource):
    """enables logged in user to refresh their expired token"""
    decorators = [auth.login_required]

    def get(self):
        return get_auth_token()


class BucketListsAPI(Resource):
    """ creates new bucketlists and fetches existing bucketlists"""
    decorators = [auth.login_required]

    def __init__(self):

        self.reqparse = reqparse.RequestParser(bundle_errors=True)
        self.reqparse.add_argument("name", type=str, required=True,
                                   help="No bucketlist name provided")
        super(BucketListsAPI, self).__init__()

    def get(self):
        """
        get bucketlists
        :return: 
        """
        token = request.headers.get("token","")
        user = g.user
        if user.verify_auth_token(token):
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

        return {"message": "Invalid token"}



    def post(self):
        """
        creates new bucketlists
        """
        token = request.headers.get("token","")

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
    pass



class BucketListItemAPI(Resource):
    """Create a new item in bucket list"""
    decorators = [auth.login_required]
    pass



class BucketListItemsAPI(Resource):
    """Updates or deletes a single bucketlist item"""
    decorators = [auth.login_required]
    pass

#################################################################################################################
# POST /auth/login                            Logs a user in

# POST /auth/register                         Register a user

# POST /bucketlists/                          Create a new bucket list
# GET /bucketlists/                           List all the create\
# d bucket lists

# GET /bucketlists/<id>                       Get single bucket list
# PUT /bucketlists/<id>                       Update this bucket list
# DELETE /bucketlists/<id>                    Delete this single bucket list

# POST /bucketlists/<id>/items/               Create a new item in bucket list

# PUT /bucketlists/<id>/items/<item_id>       Update a bucket list item
# DELETE /bucketlists/<id>/items/<item_id>    Delete an item in a bucket list
#################################################################################################################

