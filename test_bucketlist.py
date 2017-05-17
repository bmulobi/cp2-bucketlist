import json
import os
import unittest, time

from app import create_app, db, models


class BucketlistTestCase(unittest.TestCase):
    """This class represents the bucketlist test case"""

    def setUp(self):
        """Define test variables and initialize app."""
        self.app = create_app(config_name="testing")
        self.client = self.app.test_client

        # binds the app to the current context
        with self.app.app_context():
            # create all tables
            db.create_all()

    def tearDown(self):
        """teardown all initialized variables."""
        with self.app.app_context():
            # drop all tables
            db.session.remove()
            db.drop_all()

    def test_app_settings_configuration(self):
        """Test app settings"""
        app_settings = os.getenv("APP_SETTINGS")
        self.assertEqual(app_settings, "development")

    def test_prodcution_database_path(self):
        """Test path to production database"""
        database = os.getenv("DATABASE_URL")
        self.assertEqual(database, "postgresql://localhost/buckets")

    def test_app_entry_settings(self):
        """Test app entry settings"""

        executable = os.getenv("FLASK_APP")
        self.assertEqual(executable, "run.py")

    def test_api_can_register_new_user(self):
        """Test API can register new user (POST - "/bucketlists/v1.0/auth/register/')"""

        res = self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        self.assertEqual(res.status_code, 201)
        self.assertIn("ben", str(res.data))

    def test_api_rejects_invalid_user_names(self):
        """Test api checks usernames for invalid formats"""

        res = self.client().post("/bucketlists/v1.0/auth/register/",
                                 data={"username": "bendbvg987^&%^$#$__8765634&*^^%$#$#@$%",
                                       "password": 1234}
                                 )
        self.assertEqual(res.status_code, 400)
        self.assertIn('"message": "Invalid username format"', str(res.data))

    def test_api_rejects_user_names_longer_than_50_characters(self):
        """Test api checks usernames for excess length"""

        res = self.client().post("/bucketlists/v1.0/auth/register/",
                           data={"username": "greater-than-fifty-greater-than-fifty-"+
                                             "greater-than-fifty-greater-than-fifty",
                                 "password": 1234})

        self.assertEqual(res.status_code, 400)
        self.assertIn('"message": "Name should be <= 50 charac"', str(res.data))


    def test_api_can_login_valid_user(self):
        """Test API can login valid user (POST - '/bucketlists/v1.0/auth/login/')"""

        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res = self.client().post("/bucketlists/v1.0/auth/login/", data={"username_or_token": "ben", "password": 1234})
        self.assertEqual(res.status_code, 200)
        self.assertIn('"username": "ben"', str(res.data))

    def test_api_rejects_invalid_token(self):
        """Test API rejects invalid token"""
        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res = self.client().post("/bucketlists/v1.0/auth/login/", data={"username_or_token": "ben", "password": 1234})
        result_in_json = json.loads(res.data.decode("utf-8"))
        token = result_in_json['token']

        corrupted_token = token + "additional-characters"
        res2 = self.client().post("/bucketlists/v1.0/", data={"name": "make billions"}, headers={"token": corrupted_token})
        self.assertEqual(res2.status_code, 403)
        self.assertIn('"message": "Invalid token"', str(res2.data))

    def test_api_rejects_expired_token(self):
        """Test API rejects expired token"""
        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        self.client().post("/bucketlists/v1.0/auth/login/", data={"username_or_token": "ben", "password": 1234})

        user = models.Users("ben","1234")
        new_token = user.generate_auth_token(2)
        time.sleep(5)
        res2 = self.client().post("/bucketlists/v1.0/", data={"name": "make billions"},
                                  headers={"token": new_token})
        self.assertEqual(res2.status_code, 403)
        self.assertIn('"message": "Expired token, "', str(res2.data))

    def test_api_can_create_new_bucketlist(self):
        """Test API can create bucketlist (POST - '/bucketlists/v1.0/')"""

        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res1 = self.client().post("/bucketlists/v1.0/auth/login/", data={"username_or_token": "ben", "password": 1234})
        result_in_json = json.loads(res1.data.decode("utf-8"))
        token = result_in_json['token']

        res2 = self.client().post("/bucketlists/v1.0/", data={"name":"make billions"}, headers={"token":token})
        self.assertEqual(res2.status_code, 201)
        self.assertIn('"name": "make billions"', str(res2.data))

    def test_api_rejects_invalid_bucket_names(self):
        """Test api checks bucket names for invalid formats"""

        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res1 = self.client().post("/bucketlists/v1.0/auth/login/", data={"username_or_token": "ben", "password": 1234})
        result_in_json = json.loads(res1.data.decode("utf-8"))
        token = result_in_json['token']
        res2 = self.client().post("/bucketlists/v1.0/",
                                  data={"name": ["(**^%$$#@!#$&*()&*^%$%$#@*&*&%$%@#"]},
                                  headers={"token": token}
                                  )
        self.assertEqual(res2.status_code, 400)
        self.assertIn('"message": "Invalid bucketlist name format"', str(res2.data))

    def test_api_rejects_bucket_names_longer_than_50_characters(self):
        """Test api checks bucket names for excess length"""

        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res1 = self.client().post("/bucketlists/v1.0/auth/login/",
                                  data={"username_or_token": "ben", "password": 1234})
        result_in_json = json.loads(res1.data.decode("utf-8"))
        token = result_in_json['token']
        res2 = self.client().post("/bucketlists/v1.0/",
                                  data={"name": "greater-than-fifty-greater-than-fifty-"+
                                  "greater-than-fifty-greater-than-fifty"},
                                  headers={"token": token}
                                  )
        self.assertEqual(res2.status_code, 400)
        self.assertIn('"message": "Name should be <= 50 charac"', str(res2.data))

    def test_bucketlist_creation_requires_name_parameter(self):
        """Test API requires bucket name in order to create it"""

        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res = self.client().post("/bucketlists/v1.0/auth/login/",
                                  data={"username_or_token": "ben", "password": 1234})
        result_in_json = json.loads(res.data.decode("utf-8"))
        token = result_in_json['token']
        res = self.client().post("/bucketlists/v1.0/", headers={"token":token})
        self.assertEqual(res.status_code, 400)
        self.assertIn("No bucketlist name provided", str(res.data))

    def test_api_can_get_all_bucketlists_for_current_user(self):
        """Test API can get bucketlists for current user (GET request)."""

        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res1 = self.client().post("/bucketlists/v1.0/auth/login/", data={"username_or_token": "ben", "password": 1234})
        result_in_json = json.loads(res1.data.decode("utf-8"))
        token = result_in_json['token']
        self.client().post("/bucketlists/v1.0/", data={"name": "make billions"}, headers={"token":token})
        self.client().post("/bucketlists/v1.0/", data={"name": "live to be 100"}, headers={"token":token})

        res3 = self.client().get("/bucketlists/v1.0/", headers={"token":token})
        self.assertEqual(res3.status_code, 200)
        self.assertIn("make billions" and "live to be 100", str(res3.data))

    def test_api_can_get_bucketlist_by_id(self):
        """Test API can get a single bucketlist by using it's id."""

        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res1 = self.client().post("/bucketlists/v1.0/auth/login/", data={"username_or_token": "ben", "password": 1234})
        result_in_json = json.loads(res1.data.decode("utf-8"))
        token = result_in_json['token']

        self.client().post("/bucketlists/v1.0/", data={"name": "live to be 100"}, headers={"token": token})
        result = self.client().get("/bucketlists/v1.0/1", headers={"token": token})

        self.assertEqual(result.status_code, 200)
        self.assertIn("live to be 100", str(result.data))

    def test_api_rejects_non_existent_bucketlist_id(self):
        """Test API rejects non existent bucketlist id."""

        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res1 = self.client().post("/bucketlists/v1.0/auth/login/", data={"username_or_token": "ben", "password": 1234})
        result_in_json = json.loads(res1.data.decode("utf-8"))
        token = result_in_json['token']

        result = self.client().get("/bucketlists/v1.0/1", headers={"token": token})

        self.assertEqual(result.status_code, 404)

    def test_bucketlist_can_be_edited(self):
        """Test API can edit an existing bucketlist. (PUT request)"""
        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res1 = self.client().post("/bucketlists/v1.0/auth/login/", data={"username_or_token": "ben", "password": 1234})
        result_in_json = json.loads(res1.data.decode("utf-8"))
        token = result_in_json['token']
        self.client().post("/bucketlists/v1.0/", data={"name": "make billions"}, headers={"token": token})
        res2 = self.client().put("/bucketlists/v1.0/1",data={"name": "make trillions"}, headers={"token": token})
        self.assertEqual(res2.status_code, 200)
        results = self.client().get("/bucketlists/v1.0/1", headers={"token": token})
        self.assertIn('"name": "make trillions"', str(results.data))

    def test_bucketlist_deletion(self):
        """Test API can delete an existing bucketlist. (DELETE request)."""
        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res1 = self.client().post("/bucketlists/v1.0/auth/login/", data={"username_or_token": "ben", "password": 1234})
        result_in_json = json.loads(res1.data.decode("utf-8"))
        token = result_in_json['token']
        self.client().post("/bucketlists/v1.0/", data={"name": "make billions"}, headers={"token": token})
        self.client().delete("/bucketlists/v1.0/1", headers={"token": token})
        res2 = self.client().get("/bucketlists/v1.0/1", headers={"token": token})

        self.assertEqual(res2.status_code, 404)

    def test_can_create_new_item_in_bucketlist(self):
        """Test API can create new item in bucketlist. (POST request)."""
        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res1 = self.client().post("/bucketlists/v1.0/auth/login/", data={"username_or_token": "ben", "password": 1234})
        result_in_json = json.loads(res1.data.decode("utf-8"))
        token = result_in_json['token']
        self.client().post("/bucketlists/v1.0/", data={"name": "make billions"}, headers={"token": token})
        res2 = self.client().post("/bucketlists/v1.0/1/items/", data={"name": "make app"}, headers={"token": token})

        self.assertEqual(res2.status_code, 201)

    def test_api_rejects_invalid_item_names(self):
        """Test API can create new item in bucketlist. (POST request)."""
        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res1 = self.client().post("/bucketlists/v1.0/auth/login/",
                                  data={"username_or_token": "ben", "password": 1234})
        result_in_json = json.loads(res1.data.decode("utf-8"))
        token = result_in_json['token']
        self.client().post("/bucketlists/v1.0/", data={"name": "make billions"}, headers={"token": token})
        res2 = self.client().post("/bucketlists/v1.0/1/items/", data={"name": ("()**^%$%$#&^&%^%$$%$$^^^*")}, headers={"token": token})

        self.assertEqual(res2.status_code, 400)
        self.assertIn('"message":"Invalid item name format"', str(res2.data))


    def test_can_update_an_item_in_bucketlist(self):
        """Test API can update an item in bucketlist. (POST request)."""
        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res1 = self.client().post("/bucketlists/v1.0/auth/login/", data={"username_or_token": "ben", "password": 1234})
        result_in_json = json.loads(res1.data.decode("utf-8"))
        token = result_in_json['token']
        self.client().post("/bucketlists/v1.0/", data={"name": "make billions"}, headers={"token": token})
        self.client().post("/bucketlists/v1.0/1/items/", data={"name": "make app"}, headers={"token": token})
        res2 = self.client().put("/bucketlists/v1.0/1/items/1", data={"name": "updated app"}, headers={"token": token})

        self.assertEqual(res2.status_code, 201)

    def test_can_delete_an_item_in_bucketlist(self):
        """Test API can delete an item in bucketlist. (DELETE request)."""
        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res1 = self.client().post("/bucketlists/v1.0/auth/login/", data={"username_or_token": "ben", "password": 1234})
        result_in_json = json.loads(res1.data.decode("utf-8"))
        token = result_in_json['token']
        self.client().post("/bucketlists/v1.0/", data={"name": "make billions"}, headers={"token": token})
        res2 = self.client().post("/bucketlists/v1.0/1/items/", data={"name": "make app"}, headers={"token": token})
        self.assertEqual(res2.status_code, 201)
        self.client().delete("/bucketlists/v1.0/1/items/1", data={"name": "updated app"},
                                    headers={"token": token})
        res3 = self.client().get("/bucketlists/v1.0/1", headers={"token": token})
        self.assertNotIn('"name": "make app"', str(res3.data))

# Make the tests conveniently executable
if __name__ == "__main__":
    unittest.main()