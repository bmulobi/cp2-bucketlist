from flask import request, jsonify, g
from flask_restful import Resource
from flask_restful import fields, marshal, reqparse
from passlib.apps import custom_app_context as pwd_context

from app.models import Bucketlists, Users

response_fields = {
    'id': fields.Integer,
    'name': fields.String,
    'items': fields.Nested({
    'id': fields.Integer,
    'name': fields.String,
    'date_created': fields.DateTime,
    'date_modified': fields.DateTime,
    'done': fields.Boolean,
    }),
    'date_created': fields.DateTime,
    'date_modified': fields.DateTime,
    'created_by': fields.String,
}


class UserRegistrationAPI(Resource):
    """ creates new users """

    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)
        self.reqparse.add_argument('username', type=str, required=True,
                                   help='No user_name provided')
        self.reqparse.add_argument('password', type=str, required=True,
                                   help='No password provided')

        super(UserRegistrationAPI, self).__init__()

    def post(self):
        args = self.reqparse.parse_args()
        username = args['username']
        password = args['password']
        password = pwd_context.encrypt(password)

        # in_system = Users.query.get(user_name=username)
        # import pdb;
        # pdb.set_trace()

        if 1:
            user = Users(username)
            user.password = password

            user.save()

            return {'id':user.id,
                    'user_name':username,
                    'date_registered':str(user.date_registered)
                    }
        return {'username': 'Username already exists'}



class UserLoginAPI(Resource):
    """ Enables log in for registered users """
    pass

    # def __init__(self):
    #     self.reqparse = reqparse.RequestParser(bundle_errors=True)
    #     self.reqparse.add_argument('user_name', type=str, required=True,
    #                                help='No bucketlist name provided')
    #     super(UserLoginAPI, self).__init__()


class BucketListsAPI(Resource):
    """ creates new bucketlists """

    def __init__(self):
        self.reqparse = reqparse.RequestParser(bundle_errors=True)
        self.reqparse.add_argument('name', type=str, required=True,
                                   help='No bucketlist name provided')
        super(BucketListsAPI, self).__init__()

    def get(self):
        """
        get bucketlists
        :return: 
        """
        bucketlists = Bucketlists.get_all()
        results = []

        for bucketlist in bucketlists:
            obj = {
                'id': bucketlist.id,
                'name': bucketlist.name,
                'date_created': bucketlist.date_created,
                'date_modified': bucketlist.date_modified
            }
            results.append(obj)
        response = jsonify(results)
        response.status_code = 200
        return response



    def post(self):
        """
        creates new bucketlists
        """
        args = self.reqparse.parse_args()
        name = args['name']

        if name:
            user_id = 1
            bucketlist = Bucketlists(name, user_id)
            bucketlist.save()
            response = jsonify({
                'id': bucketlist.id,
                'name': bucketlist.name,
                'date_created': bucketlist.date_created,
                'date_modified': bucketlist.date_modified
            })
            response.status_code = 201

            return response


class BucketListAPI(Resource):
    """Gets , updates or deletes single bucketlist"""
    pass


class BucketListItemsAPI(Resource):
    """Gets , updates or deletes single bucketlist"""
    pass


class BucketListItemAPI(Resource):
    """Gets , updates or deletes single bucketlist"""
    pass
#################################################################################################################
# POST /auth/login                            Logs a user in
# POST /auth/register                         Register a user
# POST /bucketlists/                          Create a new bucket list
# GET /bucketlists/                           List all the created bucket lists
# GET /bucketlists/<id>                       Get single bucket list
# PUT /bucketlists/<id>                       Update this bucket list
# DELETE /bucketlists/<id>                    Delete this single bucket list
# POST /bucketlists/<id>/items/               Create a new item in bucket list
# PUT /bucketlists/<id>/items/<item_id>       Update a bucket list item
# DELETE /bucketlists/<id>/items/<item_id>    Delete an item in a bucket list
#################################################################################################################

