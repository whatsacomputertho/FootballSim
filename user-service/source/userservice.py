from flask import Flask, request
from flask_mysqldb import MySQL
from dotenv import load_dotenv
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
import os, logging, bcrypt, uuid, sys, json, jwt, time

import werkzeug

#Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s: %(message)s', datefmt='%d-%b-%Y %H:%M:%S')
log = logging.getLogger()

#Load environment variables
load_dotenv('./source/.env')

#Initialize flask application
app = Flask(__name__)
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST', 'localhost')
app.config['MYSQL_PORT'] = int(os.environ.get('MYSQL_PORT', 3306))
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD', 'None')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB', 'None')
app.config['MYSQL_CHARSET'] = os.environ.get('MYSQL_CHARSET', 'utf8')

#Initialize the mysql extension
mysql = MySQL(app)

#Function checks an expected unique response from MySQL for its length and raises an exception if not unique
def check_unique_response(response, success_log, error_message_none, error_message_else):
    if len(response) == 1:
        log.info(success_log)
    elif len(response) == 0:
        raise Exception(error_message_none)
    else:
        raise Exception(error_message_else)

#Function checks an expected empty response from MySQL for its length and raises an exception if not empty
def check_empty_response(response, success_log, error_message):
    if len(response) == 0:
        log.info(success_log)
    else:
        raise Exception(error_message)

#Function checks to make sure that the desired key is in the dict, if not it raises an exception
def get_value_from_dict(key, dict, error_message):
    if key in dict.keys():
        return dict[key]
    else:
        raise Exception(error_message)

#Function checks to make sure that a key in a list of keys is in the dict
#If it is, it adds the value to the return values, if none are present, it raises an exception
def get_values_from_dict(keys, dict, error_message):
    values = {}
    for key in keys:
        if key in dict.keys():
            values[key] = dict[key]
    if len(values.keys()) == 0:
        raise Exception(error_message)
    else:
        return values

#Function hashes a password that it is given and returns its hashed variant
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf8'), salt).decode('utf8')
    return hashed_password

#Function generates a new refresh token corresponding to the given userid using the given database cursor
def generate_refresh_token(userid, cursor):
    #Generate the token and its properties
    refresh = uuid.uuid4().hex
    expires = (datetime.today() + timedelta(days=30)).strftime('%Y-%m-%d')
    valid = True

    #Add the refresh token to the database
    cursor.execute('''INSERT INTO refresh (userid, token, expires, valid) VALUES ({}, "{}", "{}", {})'''.format(userid, refresh, expires, valid))
    mysql.connection.commit()

    #Return the token for checking
    return refresh

#Function updates a user's credentials given the user's ID and the credentials to update, as well as a database cursor
def update_user_creds(userid, email, password, cursor):
    if email != None and password != None:
        cursor.execute('''UPDATE user SET email="{}", password="{}" WHERE id={}'''.format(email, password, userid))
    elif email != None:
        cursor.execute('''UPDATE user SET email="{}" WHERE id={}'''.format(email, userid))
    elif password != None:
        cursor.execute('''UPDATE user SET password="{}" WHERE id={}'''.format(password, userid))
    else:
        raise Exception("No credentials to update were provided")
    mysql.connection.commit()
    log.info("Updated the information for the provided user")

#Function checks a user's updated credentials given the user's ID and the updated credentials, as well as a database cursor
def check_user_update(userid, email, password, cursor):
    log.info("Checking to make sure the update was successful")
    if email != None and password != None:
        cursor.execute('''SELECT email, password FROM user WHERE id={} AND active={} AND email="{}" AND password="{}"'''.format(userid, True, email, password))
    elif email != None:
        cursor.execute('''SELECT email, password FROM user WHERE id={} AND active={} AND email="{}"'''.format(userid, True, email))
    elif password != None:
        cursor.execute('''SELECT email, password FROM user WHERE id={} AND active={} AND password="{}"'''.format(userid, True, password))
    else:
        raise Exception("No credentials to check were provided")
    response = cursor.fetchall()
    return response

#Function reads the private key from the specified path to the private key on the server
def read_private_key():
    private_key_path = os.environ.get('PRIVATE_KEY_PATH', '')
    if private_key_path != '':
        private_key = open(private_key_path, 'r').read()
        key = serialization.load_ssh_private_key(private_key.encode(), password=b'')
        return key
    else:
        raise Exception("The token could not be generated")

#Check the server secret against the provided secret in a request body
def check_secret(secret):
    server_secret = os.environ.get('SECRET_KEY', '')
    if server_secret != '':
        if secret == server_secret:
            return True
    return False

#Function reads the public key from the specified path to the public key on the server
def read_public_key():
    public_key_path = os.environ.get('PUBLIC_KEY_PATH', '')
    if public_key_path != '':
        public_key = open(public_key_path, 'r').read()
        key = serialization.load_ssh_public_key(public_key.encode())
        return key
    else:
        raise Exception("The public key could not be retrieved")

#Function generates an access token given the user's id
def generate_access_token(userid):
    expires = time.mktime((datetime.now() + timedelta(seconds=100)).timetuple())
    userdict = { "iss" : "whatsacomputertho", "sub" : userid, "exp" : expires }
    token = jwt.encode(payload=userdict, key=read_private_key(), algorithm='RS256')
    return token

#Function validates and decodes 
def decode_access_token(access):
    try:
        public_key = read_public_key()
        token = jwt.decode(jwt=access, key=public_key, algorithms=['RS256'])
        return token
    except Exception as e:
        raise Exception("The provided access token could not be decoded")

@app.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(error):
    return { "status" : "error", "message" : "The provided request route does not exist" }

@app.route('/api/v0/user/login/', methods=['POST'])
def login():
    try:
        #Receive email and password from request body
        body = json.loads(request.data)
        email = get_value_from_dict('email', body, 'No email was provided in the login request')
        password = get_value_from_dict('password', body, 'No password was provided in the login request')
        log.info("User {} attempting login, proceeding to check if user exists".format(email))

        #Query database for user matching provided email
        cursor = mysql.connection.cursor()
        cursor.execute('''SELECT id, password FROM user WHERE email="{}" AND active={}'''.format(email, True))
        response = cursor.fetchall()

        #Check if there is a unique user matching the provided email
        check_unique_response(
            response,
            "User {} exists and is active, proceeding to check if password is a match".format(email),
            "There is no active SportSim user with this email",
            "There are multiple active SportSim users with this email"
        )
        
        #Check if password is a match
        if bcrypt.checkpw(password.encode('utf8'), response[0][1].encode('utf8')):
            log.info("Provided password for user {} mathces, proceeding to generate tokens".format(email))
        else:
            log.info("Provided password for user {} does not match, sending error response".format(email))
            raise Exception("The provided password is incorrect")
        
        #Query database for existing refresh token corresponding to the user
        userid = response[0][0]
        cursor.execute('''SELECT id, token FROM refresh WHERE userid={} AND valid={} AND expires>"{}" ORDER BY expires DESC'''.format(userid, True, datetime.today().strftime('%Y-%m-%d')))
        response = cursor.fetchall()

        #Check if there is a valid existing session corresponding to the user
        if len(response) == 0:
            #If not, create one for the user
            log.info("Found no valid refresh token for user {}".format(email))
            log.info("Creating new refresh token for user {}".format(email))
            refresh = generate_refresh_token(userid, cursor)

            #Check the database to make sure refresh token has been created
            cursor.execute('''SELECT token FROM refresh WHERE token="{}"'''.format(refresh))
            response = cursor.fetchall()
            check_unique_response(
                response,
                "Refresh token created successfully for user {}".format(email),
                "There was an error creating the refresh token for user {}".format(email),
                "Multiple refresh tokens with the generated hash already exist".format(email)
            )

            #Create access token for the user
            log.info("Creating access token for user {}".format(email))
            access = generate_access_token(userid)
            log.info("Access token created successfully for user {}".format(email))    

            return { "status" : "success", "message" : "Created refresh token and access token for user {} successfully".format(email), "refresh" : refresh, "access" : access }
        else:
            #If so, return it to the user
            log.info("Found valid refresh token for user {}".format(email))

            #Also before returning it to the user, encode the user as a JWT
            log.info("Creating access token for user {}".format(email))

            #Create JWT with user info
            access = generate_access_token(userid)

            return { "status" : "success", "message" : "Found valid refresh token for user {}".format(email), "refresh" : response[0][1] , "access" : access }
    except Exception as e:
        return { "status" : "error", "message" : str(e) }

@app.route('/api/v0/user/generate/', methods=['POST'])
def generate():
    try:
        #Receive refresh token from request body
        body=json.loads(request.data)
        token = get_value_from_dict('refresh', body, 'No refresh token was provided in the generate access token request')

        #Generate the current date
        date = datetime.today().strftime('%Y-%m-%d')

        #Instantiate a database cursor
        cursor = mysql.connection.cursor()
        
        #Query database for refresh token from request body
        log.info("Token received from user, attempting to validate")
        cursor.execute('''SELECT userid FROM refresh WHERE token="{}" AND valid={} AND expires>"{}"'''.format(token, True, date))
        response = cursor.fetchall()

        #Check if there is a corresponding refresh token
        check_unique_response(
            response,
            "Found a valid refresh token matching the provided token",
            "No valid refresh tokens match the provided token",
            "Multiple valid refresh tokens match the provided token"
        )

        #If so, generate the user's access token
        access = generate_access_token(response[0][0])
        
        #If there is only one corresponding session that is valid, return the valid token
        return { "status" : "success", "message" : "Generated a new access token", "access" : access }
    except Exception as e:
        return { "status" : "error", "message" : str(e) }

@app.route('/api/v0/user/register/', methods=['POST'])
def register():
    try:
        #Receive email and password from request body, encrypt password
        body = json.loads(request.data)
        email = get_value_from_dict('email', body, 'No email was provided in the register request')
        password = get_value_from_dict('password', body, 'No password was provided in the register request')
        hashed_password = hash_password(password)

        #Query database for user matching provided email
        cursor = mysql.connection.cursor()
        cursor.execute('''SELECT id, password FROM user WHERE email="{}"'''.format(email))
        response = cursor.fetchall()

        #Check if there is any user matching the provided email
        check_empty_response(
            response,
            "Creating new account for user {}".format(email),
            "A user already exists with this email"
        )
        
        #Create the account in the database
        cursor.execute('''INSERT INTO user (email, password, active) VALUES ("{}", "{}", {})'''.format(email, hashed_password, True))
        mysql.connection.commit()

        #Query the database for user ID (and to make sure the account was created)
        cursor.execute('''SELECT id FROM user WHERE email="{}" AND password="{}" AND active={}'''.format(email, hashed_password, True))
        response = cursor.fetchall()

        #Check if there is a unique user matching the provided email
        check_unique_response(
            response,
            "User {} created successfully".format(email),
            "There was an error creating an account for user {}".format(email),
            "Multiple accounts already exist with the email {}".format(email)
        )
        
        #Query database for any existing refresh tokens
        userid = response[0][0]
        cursor.execute('''SELECT token FROM refresh WHERE userid={} AND valid={} AND expires>{} ORDER BY expires DESC'''.format(userid, True, datetime.today().strftime('%Y-%m-%d')))
        response = cursor.fetchall()

        #Check if there is a valid existing refresh token corresponding to the user
        if len(response) == 0:
            #If not, create one for the user
            log.info("Found no valid refresh token for user {}".format(email))
            log.info("Creating new refresh token for user {}".format(email))
            refresh = generate_refresh_token(userid, cursor)

            #Check the database to make sure refresh token has been created
            cursor.execute('''SELECT token FROM refresh WHERE token="{}"'''.format(refresh))
            response = cursor.fetchall()
            check_unique_response(
                response,
                "Refresh token created successfully for user {}".format(email),
                "There was an error creating the refresh token for user {}".format(email),
                "Multiple refresh tokens with the generated hash already exist".format(email)
            )

            #Create access token for the user
            log.info("Creating access token for user {}".format(email))
            access = generate_access_token(userid)
            log.info("Access token created successfully for user {}".format(email))    

            return { "status" : "success", "message" : "Created refresh token and access token for user {} successfully".format(email), "refresh" : refresh, "access" : access }
        else:
            #If so, return it to the user
            log.info("Found valid refresh token for user {}".format(email))

            #Also before returning it to the user, encode the user as a JWT
            log.info("Creating access token for user {}".format(email))

            #Create JWT with user info
            access = generate_access_token(userid)

            return { "status" : "success", "message" : "Found valid refresh token for user {}".format(email), "refresh" : response[0][0] , "access" : access }
    except Exception as e:
        return { "status" : "error", "message" : str(e) }

@app.route('/api/v0/user/update/', methods=['PUT'])
def update():
    try:
        #Receive token, email, and password from request body
        body          = json.loads(request.data)
        token         = get_value_from_dict('access', body, 'No access token was provided in the user update request')
        updated_creds = get_values_from_dict(['email', 'password'], body, 'No email or password was provided in the user update request')
        if 'email' in updated_creds.keys():
            email = updated_creds['email']
        else:
            email = None
        if 'password' in updated_creds.keys():
            hashed_password = hash_password(updated_creds['password'])
        else:
            hashed_password = None
        
        #Validate the access token
        access = decode_access_token(token)
        userid = get_value_from_dict('sub', access, 'No subject was found in the provided access token')

        #Instantiate a database cursor and proceed to check for a user matching the given id
        cursor = mysql.connection.cursor()
        cursor.execute('''SELECT id, email, password FROM user WHERE id={} AND active={}'''.format(userid, True))
        response = cursor.fetchall()
        check_unique_response(
            response,
            'Found a unique active user matching the provided id',
            'No user found matching the provided id',
            'Multiple users found matching the provided id'
        )

        #If a unique user is found, proceed to update the information for that user
        update_user_creds(response[0][0], email, hashed_password, cursor)

        #Check if the update was successful
        response = check_user_update(response[0][0], email, hashed_password, cursor)
        check_unique_response(
            response,
            'User update was successful',
            "There was an error updating the provided user's information",
            'Multiple users found matching the updated information'
        )
        
        #If no exception was raised by this point, the user was successfully deactivated
        return { "status" : "success", "message" : "User information was successfully updated" }
    except Exception as e:
        return { "status" : "error", "message" : str(e) }

@app.route('/api/v0/user/logout/', methods=['PUT'])
def logout():
    try:
        #Receive token from request body
        body = json.loads(request.data)
        token = get_value_from_dict('access', body, 'No access token was provided in the logout request')
        
        #Validate the access token
        access = decode_access_token(token)
        userid = get_value_from_dict('sub', access, 'No subject was found in the provided access token')

        #Instantiate a database cursor and proceed to check for a user matching the given id
        log.info("User attempting to logout")
        cursor = mysql.connection.cursor()
        cursor.execute('''SELECT id FROM user WHERE id={} AND active={}'''.format(userid, True))
        response = cursor.fetchall()
        check_unique_response(
            response,
            'Found a unique active user matching the provided id',
            'No user found matching the provided id',
            'Multiple users found matching the provided id'
        )

        #If a unique user is found, proceed to deactivate the refresh tokens for that user
        log.info("Deactivating the user's refresh tokens")
        userid = response[0][0]
        cursor.execute('''UPDATE refresh SET valid={} WHERE userid={}'''.format(False, userid))
        mysql.connection.commit()

        #Check if the deactivation worked
        log.info("Checking to make sure the deactivation was successful")
        cursor.execute('''SELECT token FROM refresh WHERE valid={} AND userid={}'''.format(True, userid))
        response = cursor.fetchall()
        check_empty_response(
            response,
            'Refresh tokens successfully deactivated',
            'There was an error deactivating the provided user, user was not deactivated'
        )
        return { "status" : "success", "message" : "User was successfully logged out" }
    except Exception as e:
        return { "status" : "error", "message" : str(e) }

@app.route('/api/v0/user/deactivate/', methods=['PUT'])
def deactivate():
    try:
        #Receive token from request body
        body = json.loads(request.data)
        token = get_value_from_dict('access', body, 'No access token was provided in the deactivation request')
        
        #Validate the access token
        access = decode_access_token(token)
        userid = get_value_from_dict('sub', access, 'No subject was found in the provided access token')

        #Instantiate a database cursor and proceed to check for a user matching the given id
        log.info("User attempting to deactivate")
        cursor = mysql.connection.cursor()
        cursor.execute('''SELECT id FROM user WHERE id={} AND active={}'''.format(userid, True))
        response = cursor.fetchall()
        check_unique_response(
            response,
            'Found a unique active user matching the provided id',
            'No user found matching the provided id',
            'Multiple users found matching the provided id'
        )

        #If a unique user is found, proceed to deactivate the refresh tokens for that user
        log.info("Deactivating the user's refresh tokens")
        userid = response[0][0]
        cursor.execute('''UPDATE refresh SET valid={} WHERE userid={}'''.format(False, userid))
        mysql.connection.commit()

        #Check if the deactivation worked
        log.info("Checking to make sure the deactivation was successful")
        cursor.execute('''SELECT token FROM refresh WHERE valid={} AND userid={}'''.format(True, userid))
        response = cursor.fetchall()
        check_empty_response(
            response,
            'Refresh tokens successfully deactivated',
            'There was an error deactivating the provided user, user was not deactivated'
        )

        #If a unique user is found, proceed to deactivate that user
        log.info("Deactivating the user's account")
        cursor.execute('''UPDATE user SET active={} WHERE id={}'''.format(False, userid))
        mysql.connection.commit()

        #Check if deactivation worked
        log.info("Checking to make sure deactivation was successful")
        cursor.execute('''SELECT active FROM user WHERE id={} AND active={}'''.format(userid, False))
        response = cursor.fetchall()
        check_unique_response(
            response,
            'User deactivation was successful',
            'There was an error deactivating the provided user, user was logged out but not deactivated',
            'Multiple deactivated users found matching the provided id'
        )
        
        #If no exception was raised by this point, the user was successfully deactivated
        return { "status" : "success", "message" : "User was successfully deactivated" }
    except Exception as e:
        return { "status" : "error", "message" : str(e) }

@app.route('/api/v0/user/killswitch/', methods=['PUT'])
def killswitch():
    try:
        #Receive token from request body
        body = json.loads(request.data)
        secret = get_value_from_dict('secret', body, 'The provided request route does not exist')

        #Check if the secret matches the server-side secret
        if check_secret(secret):
            log.info("Admin secret detected, proceeding to invalidate refresh tokens")
            cursor = mysql.connection.cursor()
            cursor.execute('''UPDATE refresh SET valid={}'''.format(False))
            mysql.connection.commit()
            log.info("All refresh tokens were invalidated")
            return { "status" : "success", "message" : "All refresh tokens were invalidated" }
        else:
            raise Exception('The provided request route does not exist')
    except Exception as e:
        return { "status" : "error", "message" : str(e) }

@app.route('/api/v0/user/prune/', methods=['PUT'])
def prune():
    try:
        #Receive token from request body
        body = json.loads(request.data)
        secret = get_value_from_dict('secret', body, 'The provided request route does not exist')

        #Check if the secret matches the server-side secret
        if check_secret(secret):
            log.info("Admin secret detected, proceeding to prune refresh tokens")
            cursor = mysql.connection.cursor()
            cursor.execute('''DELETE FROM refresh WHERE valid={}'''.format(False))
            mysql.connection.commit()
            log.info("All refresh tokens were pruned, proceeding to prune inactive users")
            cursor.execute('''DELETE FROM user WHERE active={}'''.format(False))
            mysql.connection.commit()
            log.info("All inactive users were pruned")
            return { "status" : "success", "message" : "All inactive users and invalid refresh tokens were pruned" }
        else:
            raise Exception('The provided request route does not exist')
    except Exception as e:
        return { "status" : "error", "message" : str(e) }