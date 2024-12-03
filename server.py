# Shajira Guzman

import time
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes #new imports
from werkzeug.security import generate_password_hash
from argon2 import PasswordHasher 
import jwt
import base64
import sqlite3
import os
import uuid

# generate flask app
app = Flask(__name__)

# store keys with their exp time
keys = {}

# not in use
requestTimestamps = {}

# password hasher
ph = PasswordHasher(
    time_cost=3,
    memory_cost=2**16,
    parallelism=2,
    hash_len=32,
    salt_len=16
)

# AES encryption key
aesKey = os.getenv("NOT_MY_KEY")

if aesKey is None:
    raise ValueError("Encryption key (NOT_MY_KEY) not set in the environment.")


# create database with tables for keys, users, and auth logs
def createDatabase():
    try:
        connection = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = connection.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,  
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        ''')
        connection.commit()
        print("Table created successfully or already exists.")
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

    connection.close()

createDatabase()


# register a new user with hashed passwords
@app.route('/register', methods=['POST'])
def register():

    data = request.get_json()
    username = data.get('username')
    email = data.get('email')

    # check if username and email are provided
    if not username or not email:
        return jsonify({"error": "Username and email are required!"}), 400

    # craete secure password using UUIDv4
    pw = str(uuid.uuid4())

    # hash the password
    hashedPW = ph.hash(pw)

    # insert the user into the database if it doesn't exist
    try:
        connection = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = connection.cursor()

        cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email))
        userExists = cursor.fetchone()
        if userExists:
            return jsonify({"error": "Username or email already taken."}), 400

        cursor.execute('''
            INSERT INTO users (username, password_hash, email) 
            VALUES (?, ?, ?)
        ''', (username, hashedPW, email))

        connection.commit()
        connection.close()

        # return the pw
        return jsonify({"password": pw}), 201

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        return jsonify({"error": "Database error occurred."}), 500



# encrypts private RSA key
def encryptKey(data: bytes, key: bytes) -> bytes:

    # 16 byte initialization vector
    iv = os.urandom(16)
    # cipher object using AES with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # pad data to be an AES block of 16 bytes
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    paddedData = padder.update(data) + padder.finalize()
    
    # encrypt the data
    encryptedData = encryptor.update(paddedData) + encryptor.finalize()
    
    return iv + encryptedData  # add iv to encrypted data


# decrypts key with AES
def decryptKey(encryptedData: bytes, key: bytes) -> bytes:

    # extract first 16 bytes
    iv = encryptedData[:16]
    ciphertext = encryptedData[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # decrypt the ciphertext
    paddedData = decryptor.update(ciphertext) + decryptor.finalize()
    
    # remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(paddedData) + unpadder.finalize()
    
    return data



# generate RSA key pairs
def generate_rsa_key():

    print("Starting Key generation")
    expired = request.args.get('expired')               # get expiration (true or false) from request

    privateKey = rsa.generate_private_key(              # generate private key and set variables
        key_size = 2048,
        public_exponent = 65537,
        backend = default_backend()
    )

    kid = str(len(keys) + 1)  

    if expired:
        expirationTime = int((datetime.utcnow() - timedelta(hours=5)).timestamp())#expirationTime = datetime.utcnow() - timedelta(days=1)  # set exp a day behind
    else:
        expirationTime = int((datetime.utcnow() + timedelta(hours=2)).timestamp())#expirationTime = datetime.utcnow() + timedelta(days=5)  # set exp to expire in 5 days

    # convert to PKCS#1 PEM
    PKCSpem = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL, 
        encryption_algorithm=serialization.NoEncryption()  
    )
    encryptedKey = encryptKey(PKCSpem, aesKey.encode('utf-8')) # encrypt key

    #store key in database
    try:
        connection = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = connection.cursor()
        cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', 
              (encryptedKey, expirationTime))
        connection.commit()
        print("Keys stored in database")
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")

    connection.close()

    return kid


# JWKS endpoint
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():

    print("start jwks endpoint")
    jwksKeys = []

    # get private keys from database
    connection = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = connection.cursor()
    cursor.execute('SELECT kid, key, exp FROM keys')
    rows = cursor.fetchall()
    connection.close()

    currentTime = int(datetime.utcnow().timestamp())

    # iterate over keys and store non expired keys
    for row in rows:
        kid, pk, exp = row
        privateKey = deserializeKey(pk) #deserialize key for public key generation
        if currentTime < exp:
            # Load the public key from the private key
            publicKey = privateKey.public_key()  
            n = publicKey.public_numbers().n.to_bytes((publicKey.public_numbers().n.bit_length() + 7) // 8, byteorder='big')
            e = publicKey.public_numbers().e.to_bytes((publicKey.public_numbers().e.bit_length() + 7) // 8, byteorder='big')
            
            # Add key details to JWKS
            jwksKeys.append({
                "kid": str(kid),
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig", 
                "n": base64.urlsafe_b64encode(n).rstrip(b'=').decode('utf-8'), 
                "e": base64.urlsafe_b64encode(e).rstrip(b'=').decode('utf-8')
            })
        #else:
            #print("found expired key!!")
    return jsonify({"keys": jwksKeys})



def deserializeKey(data):

    if isinstance(data, str):
        data = data.encode('utf-8')  # Convert to bytes
    try:
        privateKey = serialization.load_pem_private_key(
            data,
            password=None,  
            backend=default_backend()
        )
        return privateKey
    except ValueError as e:
        #print(f"Error loading private key: {e}")
        return None
  


#return a decrypted private key from database
def getKey(kid):

    try:
        connection = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = connection.cursor()
        cursor.execute('SELECT key FROM keys WHERE kid = ?', (kid,))
        row = cursor.fetchone()
        print("found data in database!")
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    connection.close()

    if row:
        #return row[0]  # returns key as a blob
        encryptedKey = row[0]
        privateKey = decryptKey(encryptedKey, aesKey.encode('utf-8'))  # decrypt the private key
        return privateKey
    return None


# returns a user if found
def getUser(username):
    try:
        connection = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = connection.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        connection.close()
        if user:
            return user[0]
        return None
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None

# rate limiter not in use
def rateLimiter(ip):

    currentTime = time.time()
    
    try:
        connection = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = connection.cursor()
        
        # query the database for the 10 most recent requests from this IP
        cursor.execute('''
            SELECT request_timestamp FROM auth_logs
            WHERE request_ip = ?
            ORDER BY request_timestamp DESC
            LIMIT 10
        ''', (ip,))
        requests = cursor.fetchall()

        connection.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False

    # if any of the 10 most recent requests occurred within the last second
    recentRequests = [
        timestamp for timestamp, in requests
        if currentTime - time.mktime(time.strptime(timestamp, "%Y-%m-%d %H:%M:%S")) < 1
    ]
    
    # if more than 10 requests within the last second, deny the request
    if len(recentRequests) > 10:
        print(f"Rate limit exceeded for IP: {ip}")
        return False

    return True




@app.route('/auth', methods=['POST'])
def authenticate():

    print("start auth")
    expired = request.args.get('expired') 
    ipAddress = request.remote_addr 

    # rate limiting check - NOT IN USE
    '''if not rateLimiter(ipAddress):
        print(f"Rate limit exceeded for IP: {ipAddress}")
        return jsonify({"error": "Too many requests. Please try again later."}), 429'''

    data = request.get_json()
    username = data.get('username') 
    user = getUser(username)
    if user is None:
        return jsonify({"error": "User not found"}), 404


    # set exp time to 5 hours behind or two hours later
    if expired:
        print("got an expired key")
        expirationTime = int((datetime.utcnow() - timedelta(hours=5)).timestamp())#expirationTime = datetime.utcnow() - timedelta(days=1)
    else: 
        expirationTime = int((datetime.utcnow() + timedelta(hours=2)).timestamp())#expirationTime = datetime.utcnow() + timedelta(hours=5)
    

    #log in database
    try:
        connection = sqlite3.connect('totally_not_my_privateKeys.db')
        cursor = connection.cursor()

        # insert log into the auth_logs table
        cursor.execute('''
            INSERT INTO auth_logs (request_ip, user_id) 
            VALUES (?, ?)
        ''', (ipAddress, user))

        connection.commit()
        print(f"Logged authentication request for user {user} from IP {ipAddress}")
    except sqlite3.Error as e:
        print(f"Error logging authentication request: {e}")

    connection.close()

    kid = generate_rsa_key()
    privateKey = getKey(kid)
    if privateKey is None:
        return jsonify({"error": "Private key not found"}), 404
    
    pk = deserializeKey(privateKey)     #deserialize the private key
    payload = {'username': username, 'exp': expirationTime}
    token = jwt.encode(payload, pk, algorithm='RS256', headers={'kid': kid})

    return jsonify(token=token)


if __name__ == '__main__':
    app.run(port=8080)
