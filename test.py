# Shajira Guzman

import unittest
import time
from server import app, deserializeKey, generate_rsa_key, getKey  # importing app from server.py
import json
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class TestApp(unittest.TestCase):


    def setUp(self):

        self.app = app.test_client()
        self.app.testing = True 


    # test the auth endpoint with valid parameters
    def testAuthValid(self):

        response = self.app.post('/auth', json={"username": "iamnew2"}) #existing username
        self.assertEqual(response.status_code, 200)  # checks for OK response
        json_data = json.loads(response.data) 
        self.assertIn('token', json_data)            # checks for token


    # test the auth endpoint with expired parameters
    def testAuthExpired(self):

        response = self.app.post('/auth?expired=true', json={"username": "iamnew2"}) #existing username
        self.assertEqual(response.status_code, 200)
        json_data = json.loads(response.data)
        self.assertIn('token', json_data)  


    # test deserialization of a valid private key
    def testDeserializeValidKey(self):

        privateKey = rsa.generate_private_key(              # generate private key and set variables
            key_size = 2048,
            public_exponent = 65537,
            backend = default_backend()
        )
        # convert to PKCS#1 PEM
        PKCSpem = privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL, 
            encryption_algorithm=serialization.NoEncryption()  
        )

        deserializedKey = deserializeKey(PKCSpem)
        self.assertIsNotNone(deserializedKey)
        self.assertTrue(isinstance(deserializedKey, rsa.RSAPrivateKey))


    # test deserialization with invalid key data
    def testDeserializeInalidKey(self):

        invalidKey = b"not a valid key"
        deserializedKey = deserializeKey(invalidKey)
        self.assertIsNone(deserializedKey)

    # test auth endpoint with valid user
    def testRegisterValid(self):
        response = self.app.post('/register', json={"username": "iamnew9", "email": "iamnew9@example.com"})
        #print(response.data)
        self.assertEqual(response.status_code, 201)  # checks for created response
        json_data = json.loads(response.data)
        self.assertIn('password', json_data)


    # test auth endpoint with non-existing user
    def testAuthInvalidUser(self):
        response = self.app.post('/auth', json={"username": "x"})
        #print(response.data)
        self.assertEqual(response.status_code, 404)
        json_data = json.loads(response.data)
        self.assertIn('error', json_data)


    # test for missing username
    def testRegisterMissingFields(self):
        response = self.app.post('/register', json={
            "username": "newuser"
        })
        self.assertEqual(response.status_code, 400)  # Missing email
        json_data = json.loads(response.data)
        self.assertIn('error', json_data)
        self.assertEqual(json_data['error'], 'Username and email are required!')

    # Test for registering with duplicate username
    def testRegisterDuplicateUsername(self):
        self.app.post('/register', json={
            "username": "duplicateuser", 
            "email": "test1@example.com"
        })
        response = self.app.post('/register', json={
            "username": "duplicateuser", 
            "email": "test2@example.com"
        })
        self.assertEqual(response.status_code, 400)  # Error because username is taken
        json_data = json.loads(response.data)
        self.assertIn('error', json_data)
        self.assertEqual(json_data['error'], 'Username or email already taken.')



if __name__ == '__main__':
    app.run(port=8080)