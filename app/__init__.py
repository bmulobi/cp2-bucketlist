from flask_api import FlaskAPI
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy

# local import
from instance.config import app_config

# initialize sql-alchemy
db = SQLAlchemy()

def create_app(config_name):

    from app.resources import (
                               BucketListsAPI,
                               UserRegistrationAPI,
                               UserLoginAPI,
                               BucketListAPI,
                               BucketListItemsAPI,
                               BucketListItemAPI,
                               GetTokenAPI
                              )


    app = FlaskAPI(__name__, instance_relative_config=True)
    app.config.from_object(app_config[config_name])
    app.config.from_pyfile("config.py")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)

    api = Api(app)

    # routes
    api.add_resource(UserRegistrationAPI, "/bucketlists/v1.0/auth/register/", endpoint="registration")
    api.add_resource(UserLoginAPI, "/bucketlists/v1.0/auth/login/", endpoint="login")
    api.add_resource(GetTokenAPI, "/bucketlists/v1.0/token/", endpoint="token")
    api.add_resource(BucketListsAPI, "/bucketlists/v1.0/", endpoint = "bucketlists")
    api.add_resource(BucketListAPI, "/bucketlists/v1.0/<id>/", endpoint="bucketlist")
    api.add_resource(BucketListItemsAPI, "/bucketlists/v1.0/<id>/items/", endpoint="items")
    api.add_resource(BucketListItemAPI, "/bucketlists/v1.0/<id>/items/<item_id>", endpoint="item")


    # @app.route('/bucketlists/", methods=["POST", "GET"])
    # def bucketlists():
    #     if request.method == "POST":
    #
    #         name = str(request.data.get("name", ""))
    #
    #         if name:
    #             bucketlist = Bucketlist(name=name)
    #             bucketlist.save()
    #             response = jsonify({
    #                 "id": bucketlist.id,
    #                 "name": bucketlist.name,
    #                 "date_created": bucketlist.date_created,
    #                 "date_modified": bucketlist.date_modified
    #             })
    #             response.status_code = 201
    #
    #             return response
    #
    #         else:
    #             return jsonify({})
    #             import pdb;
    #             pdb.set_trace()
    #     else:
    #         # GET
    #         bucketlists = Bucketlist.get_all()
    #         results = []
    #
    #         for bucketlist in bucketlists:
    #             obj = {
    #                 "id": bucketlist.id,
    #                 "name": bucketlist.name,
    #                 "date_created": bucketlist.date_created,
    #                 "date_modified": bucketlist.date_modified
    #             }
    #             results.append(obj)
    #         response = jsonify(results)
    #         response.status_code = 200
    #         return response
    #
    # @app.route("/bucketlists/<int:id>", methods=["GET", "PUT", "DELETE"])
    # def bucketlist_manipulation(id, **kwargs):
    #     # retrieve a buckelist using it"s ID
    #     bucketlist = Bucketlist.query.filter_by(id=id).first()
    #     if not bucketlist:
    #         # Raise an HTTPException with a 404 not found status code
    #         abort(404)
    #
    #     if request.method == "DELETE":
    #         bucketlist.delete()
    #         return {
    #                    "message": "bucketlist {} deleted successfully".format(bucketlist.id)
    #                }, 200
    #
    #     elif request.method == "PUT":
    #         name = str(request.data.get("name", ""))
    #         bucketlist.name = name
    #         bucketlist.save()
    #         response = jsonify({
    #             "id": bucketlist.id,
    #             "name": bucketlist.name,
    #             "date_created": bucketlist.date_created,
    #             "date_modified": bucketlist.date_modified
    #         })
    #         response.status_code = 200
    #         return response
    #     else:
    #         # GET
    #         response = jsonify({
    #             "id": bucketlist.id,
    #             "name": bucketlist.name,
    #             "date_created": bucketlist.date_created,
    #             "date_modified": bucketlist.date_modified
    #         })
    #         response.status_code = 200
    #         return response

    return app