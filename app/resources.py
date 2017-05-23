import os
import re

from flask import request, jsonify, g, url_for
from flask_restful import Resource
from flask_restful import fields, marshal, reqparse
from flask_httpauth import HTTPBasicAuth
from functools import wraps

from app import app_config
from app.models import Bucketlists, Users, BucketListItems

auth = HTTPBasicAuth()

# define format for bucketlist display
bucketlist_format = {
    "id": fields.Integer,
    "name": fields.String,
    "date_created": fields.DateTime,
    "date_modified": fields.DateTime,
    "created_by": fields.Integer

    }

# regex for data validation (name formats)
regexes = {"names": r'(\(|\+|\?|\.|\*|\^|\$|\)|\&|\[|\]|\{|\}|\||\\|\`|\~|\!|\@|\#|\%|\_|\=|\;|\:|\"|\,|\<|\>|\/)'}

# decorator for private endpoints
def authorize_token(func):
    """
    Decorator function that controls access
    based on validity of token
    """
    @wraps(func)
    def decorators(*args, **kwargs):
        # Get token from the header where the key is Authorization
        token = request.headers.get("Authorization", "")
        if not token:
            return 'Unauthorized access. Please include your authorization token', 401

        token_auth = Users.verify_auth_token(token)

        if token_auth in ["expired", "invalid"]:
            if token_auth == "expired":
                return {"message": "Expired token, request for a new one"}, 403
            else:
                return {"message": "Invalid token"}, 403

        g.user = token_auth

        return func(*args, **kwargs)
    return decorators


# token generator
def get_auth_token(expiration=600):
    """generates new token for user"""
    token = g.user.generate_auth_token(expiration=expiration)
    return jsonify({ "token": token.decode("utf-8") })


# password verifier
@auth.verify_password
def verify_password(username_or_token, password):
    """verifies user password"""
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
        """register new user"""
        args = self.reqparse.parse_args()
        username = args["username"]
        password = args["password"]

        # check username format
        if re.search(regexes["names"], username):
            return {"error": "Invalid username format"}, 400

        # check username length
        if len(str(username)) > 50:
            return {"error": "Username should not exceed 50 characters"}, 400

        # check if user exists
        if Users.query.filter_by(user_name = username).first() is not None:
            return {"username": "Username already exists"}, 400

        # get user object
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
        self.reqparse.add_argument("username", type=str, required=True,
                                   help="No username provided")
        self.reqparse.add_argument("password", type=str, help="Password has to be a string")
        super(UserLoginAPI, self).__init__()

    def post(self):
        """log in user"""
        args = self.reqparse.parse_args()
        username = args["username"]
        password = args["password"]

        # check username format
        if re.search(regexes["names"], username):
            return {"error": "Invalid username format"}, 400

        # check username length
        if len(str(username)) > 50:
            return {"error": "Username should not exceed 50 characters"}, 400

        # ensure password does not exceed 50 characters
        if password and len(str(password)) > 50:
            return {"error": "Password should not exceed 50 characters"}, 400
        # verify password
        if verify_password(username, password):

            user = g.user
            # generate token
            token = user.generate_auth_token(expiration=600)
            token = token.decode("utf-8")
            # save token in memory
            UserLoginAPI.users[user.id] = token

            response = {"id": user.id,
                        "username":user.user_name,
                        "message":"You have logged in successfully",
                        "token":token
                       }, 200
            return response

        return {"message":"Invalid username_or_token and/or password - Try again"}, 403


class UserLogOutAPI(Resource):
    """ Enables log out for logged in users """
    decorators = [auth.login_required]

    def delete(self):
        """log out user - delete user object and token"""
        # get user object
        user = g.user
        user_id = user.id

        # get user's authorization token
        token = UserLoginAPI.users.get(user_id, "")
        # delete token from memory
        if token:
            del UserLoginAPI.users[user_id]
        username = user.user_name
        # delete user object from memory and application context
        del user
        del g.user
        return {"id": user_id,
                "username": username,
                "message": "You have been logged out successfully"
                }, 200


class GetTokenAPI(Resource):
    """enables logged in user to refresh their expired token"""
    decorators = [auth.login_required]

    def get(self):
        """generates new token for user"""
        # get user object
        user = g.user
        # generate token
        token = get_auth_token()
        # save token in memory
        UserLoginAPI.users[user.id] = token.data.decode("utf-8").split('"')[3]

        return token


class BucketListsAPI(Resource):
    """ creates new bucketlists and fetches existing bucketlists"""
    decorators = [authorize_token]

    def __init__(self):

        self.reqparse = reqparse.RequestParser(bundle_errors=True)
        self.reqparse.add_argument("name", type=str, required=False,
                                   help="No bucketlist name provided")
        self.reqparse.add_argument("limit", type=int, required=False,
                                   help="Limit has to be a number between 1 and 100")
        self.reqparse.add_argument("page", type=int, required=False,
                                   help="page number has to be a number greater than zero")
        self.reqparse.add_argument("q", type=str, required=False,
                                   help="search parameter has to be a string")
        super(BucketListsAPI, self).__init__()

    def get(self):
        """gets all bucketlists belonging to user"""

        # get request data dictionary
        args = self.reqparse.parse_args()

        # get logged in user
        user = g.user
        limit = app_config[os.getenv("APP_SETTINGS")].BUCKETLISTS_PER_PAGE

        # get page to display
        page = args["page"]
        if page:
            # ensure given page number is an integer
            if not str(page).isdigit():
                return {"error": "Page number has to be an integer"}, 400

            if page < 1:
                page = 1
        else:
            # default page number
            page = 1

        # get query parameter if any
        query = args["q"]

        # get per page limit
        limit = args["limit"]

        # ensure given limit is an integer
        if not str(limit).isdigit():
            return {"error": "Limit has to be an integer"}, 400
        # ensure limit does not violate (min=1 and max=100)
        if limit:
            if limit > app_config[os.getenv("APP_SETTINGS")].MAX_BUCKETLISTS_PER_REQUEST:
                limit = app_config[os.getenv("APP_SETTINGS")].MAX_BUCKETLISTS_PER_REQUEST
            if limit < 1:
                limit = app_config[os.getenv("APP_SETTINGS")].BUCKETLISTS_PER_PAGE
        else:
            # default limit
            limit = app_config[os.getenv("APP_SETTINGS")].BUCKETLISTS_PER_PAGE
        # if user gave search term
        if query:

            # check search term format
            if re.search(regexes["names"], query):
                return {"error": "Invalid search term format"}, 400

            # check search term length
            if len(str(query)) > 30:
                return {"error": "Search term should not exceed 30 characters"}, 400
            # search parameter when given
            q = "&q={}"
            bucketlists = (Bucketlists.query.filter(Bucketlists.name.
                                                    ilike("%{}%".format(query))).
                           filter_by(created_by=user.id).paginate(page, limit, False))
            if not bucketlists:
                return {"info": "no results for search query " + query}
        else:
            # search parameter when not given
            q = ""
            query = ""
            bucketlists = (Bucketlists.query.
                           filter_by(created_by=user.id).paginate(page, limit, False))
        # set url for next page, if any
        if bucketlists.has_next:
            url_next = (url_for(request.endpoint) +
                        "?page=" + str(page + 1) +
                        "&limit=" + str(limit) +
                        q.format(query))
        else:
            url_next = "No next page"
        # set url for previous page, if any
        if bucketlists.has_prev:
            url_prev = (url_for(request.endpoint) +
                        "?page=" + str(page - 1) +
                        "&limit=" + str(limit) +
                        q.format(query))
        else:
            url_prev = "No previous page"

        return {"info": {"next_page": url_next,
                         "previous_page": url_prev,
                         "total_pages": bucketlists.pages},
                         "bucketlists": marshal(bucketlists.items,
                                                bucketlist_format)
                }, 200

    def post(self):
        """
        creates new bucketlists
        """
        user = g.user
        args = self.reqparse.parse_args()
        name = args["name"]

        if name:

            # check bucket name format
            if re.search(regexes["names"], name):
                return {"error": "Invalid bucket name format"}, 400

            # check bucket name length
            if len(str(name)) > 50:
                return {"error": "Bucket name should not exceed 50 characters"}, 400

            # check if bucket name already exists
            if Bucketlists.query.filter_by(name=name).first() is not None:
                return {"error": "Bucket name already exists"}, 400

            user_id = user.id
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


class BucketListAPI(Resource):
    """Gets , updates or deletes single bucketlist"""
    decorators = [authorize_token]

    def __init__(self):

        self.reqparse = reqparse.RequestParser(bundle_errors=True)
        self.reqparse.add_argument("name", type=str, required=True,
                                   help="No new name provided")
        super(BucketListAPI, self).__init__()

    def put(self, id):
        """update bucketlist with given id"""

        # ensure given id is an integer
        if not str(id).isdigit():
            return {"error": "Bucketlist id has to be an integer"}, 400

        args = self.reqparse.parse_args()
        name = args["name"]
        user = g.user
        if name:
            # check bucket name format
            if re.search(regexes["names"], name):
                return {"error": "Invalid bucket name format"}, 400

            # check bucket name length
            if len(str(name)) > 50:
                return {"error": "Bucket name should not exceed 50 characters"}, 400

            # check if bucket id exists
            bucket =  Bucketlists.query.filter_by(id=id, created_by=user.id).first()
            if bucket is not None:
                bucket.name = name
                bucket.update()

                return {"id": bucket.id,
                        "name": bucket.name,
                        "date_created": str(bucket.date_created),
                        "date_modified": str(bucket.date_modified)
                        }, 200
            return {"error": "the given bucket id -" + str(id) + "- does not exist"}, 404

        return {"error": "A new bucket name was not provided"}, 400

    def get(self, id):
        """fetch bucketlist with given id"""

        # ensure given id is an integer
        if not str(id).isdigit():
            return {"error": "Bucketlist id has to be an integer"}, 400

        user = g.user
        # check if bucket id exists
        bucket = Bucketlists.query.filter_by(id=id, created_by=user.id).first()
        if bucket is not None:

            response = {"id": id,
                        "name": bucket.name,
                        "items": [],
                        "date_created": str(bucket.date_created),
                        "date_modified": str(bucket.date_modified),
                        "created_by": bucket.created_by
                        }
            items = BucketListItems.query.filter_by(bucket_id=id)

            if items:
                for item in items:
                    response["items"].append(
                                            {
                                            "id": item.id,
                                            "name": item.description,
                                            "date_created": str(item.date_created),
                                            "date_modified": str(item.date_modified),
                                            "done": item.done
                                            }

                                            )
            return response, 200

        return {"error": "the given bucket id -" + str(id) + "- does not exist"}, 404

    def delete(self, id):
        """ delete bucketlist with given id """

        user = g.user

        # check if bucket id exists for current user
        bucket = Bucketlists.query.filter_by(id=id, created_by=user.id).first()
        if bucket is not None:
            bucket.delete()

            return {"bucket_id": id,
                    "created_by": user.user_name,
                    "message": "was deleted succesfully"
                    }, 200
        return {"error": "the given bucketlist id does not exist"}, 400


class BucketListItemAPI(Resource): # "/bucketlists/v1.0/<id>/items/<item_id>"
    """Updates or deletes a single bucketlist item"""
    decorators = [authorize_token]

    def __init__(self):

        self.reqparse = reqparse.RequestParser(bundle_errors=True)
        self.reqparse.add_argument("description", type=str,
                                   help="new item description must be a string")
        self.reqparse.add_argument("done", type=str,
                                   help="new item description must be a string")
        super(BucketListItemAPI, self).__init__()

    def put(self, id, item_id):
        """updates single bucketlist item"""

        # ensure id and item_id are integers
        if not str(id).isdigit() or not str(item_id).isdigit():
            return {"error": "bucket id and item_id must be integers"}, 400

        # get user details from app context
        user = g.user
        args = self.reqparse.parse_args()
        description = args["description"]
        done = args["done"]

        # ensure item status is either true or false
        if done and done not in ["true", "false"]:
            return {"error": "done (item status) is either true or false"}, 400

        if description:
            # check item name format
            if re.search(regexes["names"], description):
                return {"error": "Invalid item name format"}, 400

            # check item name length
            if len(str(description)) > 100:
                return {"error": "Item description should not exceed 100 characters"}, 400

        if not description and not done:
            return {"error": "In order to update a bucketlist item" +
                             " you must provide either a new description or status(done) or both " +
                             "and status must be either true or false"
                    }, 400

        # check if bucket id exists for current user
        if Bucketlists.query.filter_by(id=id, created_by=user.id).first():
            # check if item id exists in the bucket
            item = BucketListItems.query.filter_by(id=item_id, bucket_id=id).first()

            # if item exists, make available updates("description or done or both)
            if item:
                if description:

                    if re.search(regexes["names"], description) or len(str(description)) > 100:
                        return {"error": "the given item description should not have " +
                                         "special characters and length should not exceed 100 characters"
                                }, 400

                    if BucketListItems.query.filter_by(description=description, bucket_id=id).first():
                        return {"error": "the given item description already exists in the given bucket"}, 400
                    item.description = description
                if done:
                    item.done = done

                # save update(s)
                item.update()

                return {"item id": item_id,
                        "description": item.description,
                        "bucket_id": id,
                        "date_created": str(item.date_created),
                        "date_modified": str(item.date_modified),
                        "message": "item was updated successfully",
                        "done": item.done
                        }, 200

            return {"error": "the given item id does not exist in the given bucketlist"}, 404

        return {"error": "the given bucketlist id does not exist for the current user"}, 404

    def delete(self, id, item_id):
        """ deletes a single item given its id and bucketlist id"""

        # get current user
        user = g.user
        # ensure id and item_id are integers
        if not str(id).isdigit() or not str(item_id).isdigit():
            return {"error": "bucket id and item_id must be integers"}, 400

        # check if bucket id exists for current user
        if Bucketlists.query.filter_by(id=id, created_by=user.id).first():
            # check if item id exists in the bucket
            item = BucketListItems.query.filter_by(id=item_id, bucket_id=id).first()

            # if item exists, delete it
            if item:
                item.delete()
                return {"item_id": item.id,
                        "item_description": item.description,
                        "bucket_id": item.bucket_id,
                        "message": "item was deleted successfully"
                        }, 200

            return {"error": "the given item id does not exist in the given bucketlist"}, 404

        return {"error": "the given bucketlist id does not exist for the current user"}, 404


class BucketListItemsAPI(Resource):
    """Create a new item in bucket list"""
    decorators = [authorize_token]

    def __init__(self):

        self.reqparse = reqparse.RequestParser(bundle_errors=True)
        self.reqparse.add_argument("description", type=str, required=True,
                                   help="Item description was not provided")
        super(BucketListItemsAPI, self).__init__()

    def post(self, id):
        """Creates a single bucketlist item"""

        user = g.user
        args = self.reqparse.parse_args()
        description = args["description"]

        # ensure given id is an integer
        if not str(id).isdigit():
            return {"error": "Bucketlist id has to be an integer"}, 400

        # check if bucket id exists for current user
        bucket = Bucketlists.query.filter_by(id=id, created_by=user.id).first()
        if bucket is not None:

            if description:
                # check item name format
                if re.search(regexes["names"], description):
                    return {"error": "Invalid item name format"}, 400

                # check item name length
                if len(str(description)) > 50:
                    return {"error": "item name should not exceed 50 characters"}, 400

                if BucketListItems.query.filter_by(bucket_id=id, description=description).first():
                    return {"error": "Item name already exists in bucket id " + str(id)}, 400

                bucket_list_item = BucketListItems(description, id)
                bucket_list_item.save()

                return {"item id": bucket_list_item.id,
                        "description": bucket_list_item.description,
                        "bucket_id": id,
                        "date_creted": str(bucket_list_item.date_created),
                        "date_modified": str(bucket_list_item.date_modified),
                        "message": "was created successfully",
                        "done": bucket_list_item.done
                        }, 201
            return {"error": "please provide an item name"}, 400

        return {"error": "the bucketlist id does not exist"}, 400
