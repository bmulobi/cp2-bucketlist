import json
import unittest

from app import create_app, db


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

    def test_api_can_register_new_user(self):
        """Test API can register new user (POST - "/bucketlists/v1.0/auth/register/')"""

        res = self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        self.assertEqual(res.status_code, 201)
        self.assertIn("ben", str(res.data))

    def test_api_can_login_valid_user(self):
        """Test API can login valid user (POST - '/bucketlists/v1.0/auth/login/')"""

        res = self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res = self.client().post("/bucketlists/v1.0/auth/login/", data={"username_or_token": "ben", "password": 1234})
        self.assertEqual(res.status_code, 200)
        self.assertIn('"username": "ben"', str(res.data))

    def test_api_can_create_new_bucketlist(self):
        """Test API can create bucketlist (POST - '/bucketlists/v1.0/')"""

        self.client().post("/bucketlists/v1.0/auth/register/", data={"username": "ben", "password": 1234})
        res1 = self.client().post("/bucketlists/v1.0/auth/login/", data={"username_or_token": "ben", "password": 1234})
        result_in_json = json.loads(res1.data.decode("utf-8"))
        token = result_in_json['token']

        res2 = self.client().post("/bucketlists/v1.0/", data={"name":"make billions"}, headers={"token":token})
        self.assertEqual(res2.status_code, 201)
        self.assertIn('"name": "make billions"', str(res2.data))

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
        result = self.client().get("/bucketlists/v1.0/1")

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
        res = self.client().post("/bucketlists/v1.0/", data={"name": "make billions"})
        self.assertEqual(res.status_code, 201)
        res = self.client().put(
            "/bucketlists/1",
            data={
                "name": "Dont just eat, but also pray and love :-)"
            })
        self.assertEqual(res.status_code, 200)
        results = self.client().get("/bucketlists/1")
        self.assertIn("Dont just eat", str(results.data))

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

    def test_bucketlist_deletion(self):
        """Test API can delete an existing bucketlist. (DELETE request)."""
        rv = self.client().post(
            "/bucketlists/",
            data={"name": "Eat, pray and love"})
        self.assertEqual(rv.status_code, 201)
        res = self.client().delete("/bucketlists/1")
        self.assertEqual(res.status_code, 200)
        # Test to see if it exists, should return a 404
        result = self.client().get("/bucketlists/1")
        self.assertEqual(result.status_code, 404)

    def tearDown(self):
        """teardown all initialized variables."""
        with self.app.app_context():
            # drop all tables
            db.session.remove()
            db.drop_all()

# Make the tests conveniently executable
if __name__ == "__main__":
    unittest.main()