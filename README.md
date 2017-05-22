[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CircleCI](https://circleci.com/gh/bmulobi/cp2-bucketlist.svg?style=svg)](https://circleci.com/gh/bmulobi/cp2-bucketlist)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/4930f6247bb44a1c83867907305e1f9b)](https://www.codacy.com/app/bmulobi/cp2-bucketlist?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=bmulobi/cp2-bucketlist&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/4930f6247bb44a1c83867907305e1f9b)](https://www.codacy.com/app/bmulobi/cp2-bucketlist?utm_source=github.com&utm_medium=referral&utm_content=bmulobi/cp2-bucketlist&utm_campaign=Badge_Coverage)
# cp2-bucketlist application - FLask-RESTful API

## Introduction
A Bucket List is a list of things that one has not done before but wants to do before dying.
cp2-bucketlist is an api for online bucket list service using Flask.
cp2-bucketlist allows you to interact with the api and perform various
operations on the bucket list such as register as a user, add bucketlists and bucketlist items

## Installation

Clone the cp2-bucketlist application from GitHub:

url:
>`$ git clone https://github.com/bmulobi/cp2-bucketlist.git`

cd into the created folder and install a virtual environment

`$ python3.6 -m venv env-name`

Activate the virtual environment

`$ source env-name/bin/activate`

Install application dependencies into environment (env-name)

`$ pip install -r requirements.txt`

Export application configurations into system environment (do this from root folder)

`source .env`

Create the database and make migrations

`$ python manage.py db init`

`$ python manage.py db migrate`

`$ python manage.py db upgrade`

Start your server by running
`$ python manage.py runserver`.

Use the postman (https://www.getpostman.com/) application to test the API,
alternatively you can use curl (if familiar with terminal)

### Endpoints

Here is a list of all the endpoints in bucketlist app.

Endpoint | Functionality| Access
------------ | ------------- | -------------
POST bucketlists/v1.0/auth/register | Registers a user | PUBLIC
POST bucketlists/v1.0/auth/login | Logs a user in | PUBLIC
DELETE /bucketlists/v1.0/auth/logout/ | Logs out user | PRIVATE
GET bucketlists/v1.0/token/ | gets a fresh token | PRIVATE
POST, GET bucketlists/v1.0/ | Creates and fetches bucketlists | PRIVATE
GET, PUT, DELETE bucketlists/v1.0/&lt;int:id>&gt; | Gets and updates single bucket list with the given id | PRIVATE
POST bucketlists/v1.0/bucketlists/&lt;int:id&gt;/items/ | Creates a new item in bucket list | PRIVATE
PUT, DELETE bucketlists/v1.0/&lt;int:id&gt;/items/&lt;int:item_id&gt; | Updates and deletes bucket list item | PRIVATE

### Searching

You can search for bucketlists using the parameter `q` in the GET request.
Example:

`GET bucketlists/v1.0/?q=ben`

Returns all bucketlists with the string `ben` in their name

### Example GET response
After a successful resgistration and login, API generates an authorization token.
Pass this token in your request header, as follows.
```
headers={"Authorization": token}
```
Below is an example of a GET request for bucketlists

```
{
  "bucketlists": [
    {
      "created_by": 3,
      "date_created": "Sat, 20 May 2017 11:12:20 -0000",
      "date_modified": "Sat, 20 May 2017 11:12:20 -0000",
      "id": 1,
      "name": "bucket3"
    },
    {
      "created_by": 3,
      "date_created": "Sat, 20 May 2017 14:52:19 -0000",
      "date_modified": "Sat, 20 May 2017 14:52:19 -0000",
      "id": 6,
      "name": "ben333333"
    }
  ],
  "info": {
    "next_page": "/bucketlists/v1.0/?page=2&limit=2",
    "previous_page": "Null",
    "total_pages": 8
  }
}
```
### Testing
You can run the tests using the framework nosetests.
To run tests with nose, run `nosetests -v --with-coverage` from the terminal

### License
The API uses an MIT license
