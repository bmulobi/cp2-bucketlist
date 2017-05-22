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
                               GetTokenAPI,
                               UserLogOutAPI
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
    api.add_resource(BucketListAPI, "/bucketlists/v1.0/<int:id>", endpoint="bucketlist")
    api.add_resource(BucketListItemsAPI, "/bucketlists/v1.0/<int:id>/items/", endpoint="items")
    api.add_resource(BucketListItemAPI, "/bucketlists/v1.0/<int:id>/items/<int:item_id>", endpoint="item")
    api.add_resource(UserLogOutAPI, "/bucketlists/v1.0/auth/logout/", endpoint="logout")

    return app