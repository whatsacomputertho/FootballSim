from dotenv import load_dotenv
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
import subprocess, json, uuid, os, time, jwt

#Function reads the private key from the specified path to the private key on the server
def read_private_key():
    private_key_path = os.environ.get('PRIVATE_KEY_PATH', '')
    if private_key_path != '':
        private_key = open(private_key_path, 'r').read()
        key = serialization.load_ssh_private_key(private_key.encode(), password=b'')
        return key
    else:
        raise Exception("The token could not be generated")

#Function generates an access token given the user's id
def generate_access_token(userid):
    expires = time.mktime((datetime.now() + timedelta(seconds=100)).timetuple())
    userdict = { "iss" : "whatsacomputertho", "sub" : userid, "exp" : expires }
    token = jwt.encode(payload=userdict, key=read_private_key(), algorithm='RS256')
    return token

#Function generates an access token given the user's id
def generate_access_token_no_subject():
    expires = time.mktime((datetime.now() + timedelta(seconds=100)).timetuple())
    userdict = { "iss" : "whatsacomputertho", "exp" : expires }
    token = jwt.encode(payload=userdict, key=read_private_key(), algorithm='RS256')
    return token

##################
# Register tests #
##################

def test_register(email, password, expected_status, expected_message, test_name):
    #Format the request body
    request_body = f'{{}}'
    if email != None and password != None:
        request_body = f'{{ "email":"{email}", "password":"{password}" }}'
    elif email != None:
        request_body = f'{{ "email":"{email}" }}'
    elif password != None:
        request_body = f'{{ "password":"{password}" }}'

    #Call the api and get its response
    response = json.loads(subprocess.check_output(['curl', '-X', 'POST', '-H', 'Content-Type: application/json', '-d', request_body, f'http://{os.environ.get("HOST", "localhost")}:{os.environ.get("PORT", "8081")}/api/v0/user/register/']))

    #Check the results
    if expected_status == response['status'] and expected_message == response['message']:
        return { "test" : test_name, "passed" : True, "results" : response }
    else:
        return { "test" : test_name, "passed" : False, "results" : response }

###############
# Login tests #
###############

def test_login(email, password, expected_status, expected_message, test_name):
    #Format the request body
    request_body = f'{{}}'
    if email != None and password != None:
        request_body = f'{{ "email":"{email}", "password":"{password}" }}'
    elif email != None:
        request_body = f'{{ "email":"{email}" }}'
    elif password != None:
        request_body = f'{{ "password":"{password}" }}'
    
    #Call the api and get its response
    response = json.loads(subprocess.check_output(['curl', '-X', 'POST', '-H', 'Content-Type: application/json', '-d', request_body, f'http://{os.environ.get("HOST", "localhost")}:{os.environ.get("PORT", "8081")}/api/v0/user/login/']))

    #Check the results
    if expected_status == response['status'] and expected_message == response['message']:
        return { "test" : test_name, "passed" : True, "results" : response }
    else:
        return { "test" : test_name, "passed" : False, "results" : response }

##################
# Generate tests #
##################

def test_generate(refresh, expected_status, expected_message, test_name):
    #Format the request body
    request_body = f'{{}}'
    if refresh != None:
        request_body = f'{{ "refresh":"{refresh}" }}'
    
    #Call the api and get its response
    response = json.loads(subprocess.check_output(['curl', '-X', 'POST', '-H', 'Content-Type: application/json', '-d', request_body, f'http://{os.environ.get("HOST", "localhost")}:{os.environ.get("PORT", "8081")}/api/v0/user/generate/']))

    #Check the results
    if expected_status == response['status'] and expected_message == response['message']:
        return { "test" : test_name, "passed" : True, "results" : response }
    else:
        return { "test" : test_name, "passed" : False, "results" : response }

################
# Update tests #
################

def test_update(access, email, password, expected_status, expected_message, test_name):
    #Format the request body
    request_body = f'{{}}'
    if email != None and password != None and access != None:
        request_body = f'{{ "access":"{access}", "email":"{email}", "password":"{password}" }}'
    elif email != None and password != None:
        request_body = f'{{ "email":"{email}", "password":"{password}" }}'
    elif email != None and access != None:
        request_body = f'{{ "email":"{email}", "access":"{access}" }}'
    elif password != None and access != None:
        request_body = f'{{ "password":"{password}", "access":"{access}" }}'
    elif email != None:
        request_body = f'{{ "email":"{email}" }}'
    elif access != None:
        request_body = f'{{ "access":"{access}" }}'
    elif password != None:
        request_body = f'{{ "password":"{password}" }}'
    
    #Call the api and get its response
    response = json.loads(subprocess.check_output(['curl', '-X', 'PUT', '-H', 'Content-Type: application/json', '-d', request_body, f'http://{os.environ.get("HOST", "localhost")}:{os.environ.get("PORT", "8081")}/api/v0/user/update/']))

    #Check the results
    if expected_status == response['status'] and expected_message == response['message']:
        return { "test" : test_name, "passed" : True, "results" : response }
    else:
        return { "test" : test_name, "passed" : False, "results" : response }

################
# Logout tests #
################

def test_logout(access, expected_status, expected_message, test_name):
    #Format the request body
    request_body = f'{{}}'
    if access != None:
        request_body = f'{{ "access":"{access}" }}'

    #Call the api and get its response
    response = json.loads(subprocess.check_output(['curl', '-X', 'PUT', '-H', 'Content-Type: application/json', '-d', request_body, f'http://{os.environ.get("HOST", "localhost")}:{os.environ.get("PORT", "8081")}/api/v0/user/logout/']))

    #Check the results
    if expected_status == response['status'] and expected_message == response['message']:
        return { "test" : test_name, "passed" : True, "results" : response }
    else:
        return { "test" : test_name, "passed" : False, "results" : response }

####################
# Deactivate tests #
####################

def test_deactivate(access, expected_status, expected_message, test_name):
    #Format the request body
    request_body = f'{{}}'
    if access != None:
        request_body = f'{{ "access":"{access}" }}'
    
    #Call the api and get its response
    response = json.loads(subprocess.check_output(['curl', '-X', 'PUT', '-H', 'Content-Type: application/json', '-d', request_body, f'http://{os.environ.get("HOST", "localhost")}:{os.environ.get("PORT", "8081")}/api/v0/user/deactivate/']))

    #Check the results
    if expected_status == response['status'] and expected_message == response['message']:
        return { "test" : test_name, "passed" : True, "results" : response }
    else:
        return { "test" : test_name, "passed" : False, "results" : response }

def test():
    #Instantiate a list for the test results
    test_results = []

    #Instantiate random parameters that definitely don't exist
    random_email      = uuid.uuid4().hex + "@" + uuid.uuid4().hex + "." + uuid.uuid4().hex
    random_password   = "iamdefinitelynotapassword" + uuid.uuid4().hex
    random_refresh    = "iamdefinitelynotarefreshtoken" + uuid.uuid4().hex
    inactive_user_id  = 1
    random_access     = generate_access_token(inactive_user_id)
    empty_access      = generate_access_token_no_subject()

    #Instantiate the user parameters that we will follow throughout the creation -> deactivation process
    random_user_email      = uuid.uuid4().hex + "@" + uuid.uuid4().hex + "." + uuid.uuid4().hex
    random_user_email_2    = uuid.uuid4().hex + "@" + uuid.uuid4().hex + "." + uuid.uuid4().hex
    random_user_email_3    = uuid.uuid4().hex + "@" + uuid.uuid4().hex + "." + uuid.uuid4().hex
    random_user_password   = "iamalsodefinitelynotapassword" + uuid.uuid4().hex
    random_user_password_2 = "iamalsodefinitelynotapassword" + uuid.uuid4().hex
    random_user_password_3 = "iamalsodefinitelynotapassword" + uuid.uuid4().hex

    #########################################
    # Pre user creation empty request tests #
    #########################################################
    # Login, Register, Generate, Update, Logout, Deactivate #
    # All fully empty                                       #
    #########################################################
    try:
        login_empty_request = test_login(
            email=None,
            password=None,
            expected_status="error",
            expected_message="No email was provided in the login request",
            test_name="login with empty request body"
        )
        test_results.append(login_empty_request)

        login_no_password = test_login(
            random_user_email,
            None,
            "error",
            "No password was provided in the login request",
            "login existent user with no password"
        )
        test_results.append(login_no_password)

        login_no_email = test_login(
            None,
            random_user_password,
            "error",
            "No email was provided in the login request",
            "login existent user with no email"
        )
        test_results.append(login_no_email)

        register_no_password = test_register(
            random_user_email,
            None,
            "error",
            "No password was provided in the register request",
            "register no password"
        )
        test_results.append(register_no_password)

        register_no_email = test_register(
            None,
            random_user_password,
            "error",
            "No email was provided in the register request",
            "register no email"
        )
        test_results.append(register_no_email)

        register_empty_request = test_register(
            email=None,
            password=None,
            expected_status="error",
            expected_message="No email was provided in the register request",
            test_name="register with empty request body"
        )
        test_results.append(register_empty_request)

        generate_empty_request = test_generate(
            refresh=None,
            expected_status="error",
            expected_message="No refresh token was provided in the generate access token request",
            test_name="generate with empty request body"
        )
        test_results.append(generate_empty_request)

        update_empty_request = test_update(
            access=None,
            email=None,
            password=None,
            expected_status="error",
            expected_message="No access token was provided in the user update request",
            test_name="update with empty request body"
        )
        test_results.append(update_empty_request)

        update_only_invalid_access = test_update(
            access=random_access,
            email=None,
            password=None,
            expected_status="error",
            expected_message="No email or password was provided in the user update request",
            test_name="update with request body containing only invalid access token"
        )
        test_results.append(update_only_invalid_access)

        update_only_invalid_email = test_update(
            access=None,
            email=random_email,
            password=None,
            expected_status="error",
            expected_message="No access token was provided in the user update request",
            test_name="update with request body containing only nonexistent email"
        )
        test_results.append(update_only_invalid_email)

        update_only_invalid_password = test_update(
            access=None,
            email=None,
            password=random_password,
            expected_status="error",
            expected_message="No access token was provided in the user update request",
            test_name="update with request body containing only nonexistent password"
        )
        test_results.append(update_only_invalid_password)

        update_invalid_email_password = test_update(
            access=None,
            email=random_email,
            password=random_password,
            expected_status="error",
            expected_message="No access token was provided in the user update request",
            test_name="update with request body containing nonexistent email and password"
        )
        test_results.append(update_invalid_email_password)

        logout_empty_request = test_logout(
            access=None,
            expected_status="error",
            expected_message="No access token was provided in the logout request",
            test_name="logout with empty request body"
        )
        test_results.append(logout_empty_request)

        deactivate_empty_request = test_deactivate(
            access=None,
            expected_status="error",
            expected_message="No access token was provided in the deactivation request",
            test_name="deactivate with empty request body"
        )
        test_results.append(deactivate_empty_request)
    except Exception as e:
        print("Tests failed during empty request stage due to error: {}".format(str(e)))
        return test_results

    ########################
    # Before user creation #
    ########################################################
    # Login non existent user                              #
    # Generate access token for non existent refresh token #
    # Update user with invalid access token                #
    # Logout with invalid access token                     #
    # Deactivate user with invalid access token            #
    ########################################################
    try:
        login_nonexistent_user = test_login(
            random_email,
            random_password,
            "error",
            "There is no active SportSim user with this email",
            "login nonexistent user"
        )
        test_results.append(login_nonexistent_user)

        generate_nonexistent_refresh = test_generate(
            random_refresh,
            "error",
            "No valid refresh tokens match the provided token",
            "generate access token for non existent refresh token"
        )
        test_results.append(generate_nonexistent_refresh)

        update_garbage_access = test_update(
            "notanaccesstoken",
            random_email,
            random_password,
            "error",
            "The provided access token could not be decoded",
            "update account with garbage access token"
        )
        test_results.append(update_garbage_access)

        update_empty_access = test_update(
            empty_access,
            random_email,
            random_password,
            "error",
            "No subject was found in the provided access token",
            "update account with garbage access token"
        )
        test_results.append(update_empty_access)

        update_invalid_access = test_update(
            random_access,
            random_email,
            random_password,
            "error",
            "No user found matching the provided id",
            "update account with invalid access token"
        )
        test_results.append(update_invalid_access)

        logout_invalid_access = test_logout(
            random_access,
            "error",
            "No user found matching the provided id",
            "logout user with invalid access token"
        )
        test_results.append(logout_invalid_access)

        logout_empty_access = test_logout(
            access=empty_access,
            expected_status="error",
            expected_message="No subject was found in the provided access token",
            test_name="logout with subjectless access token"
        )
        test_results.append(logout_empty_access)

        logout_garbage_access = test_logout(
            access="notanaccesstoken",
            expected_status="error",
            expected_message="The provided access token could not be decoded",
            test_name="logout with garbage access token"
        )
        test_results.append(logout_garbage_access)

        deactivate_invalid_access = test_deactivate(
            random_access,
            "error",
            "No user found matching the provided id",
            "deactivate user with invalid access token"
        )
        test_results.append(deactivate_invalid_access)

        deactivate_empty_access = test_logout(
            access=empty_access,
            expected_status="error",
            expected_message="No subject was found in the provided access token",
            test_name="deactivate with subjectless access token"
        )
        test_results.append(deactivate_empty_access)

        deactivate_garbage_access = test_logout(
            access="notanaccesstoken",
            expected_status="error",
            expected_message="The provided access token could not be decoded",
            test_name="deactivate with garbage access token"
        )
        test_results.append(deactivate_garbage_access)
    except Exception as e:
        print("Tests failed before user creation due to error: {}".format(str(e)))
        return test_results


    ######################################
    # User Creation and subsequent tests #
    ####################################################
    # Register new user                                #
    # Login existent user                              #
    # Login existent user with wrong password          #
    # Generate access token for existent refresh token #
    # Register existent user                           #
    # Logout existent user                             #
    # Login existent user with no valid refresh token  #
    # Deactivate existent user                         #
    ####################################################
    try:
        register_new_user = test_register(
            random_user_email,
            random_user_password,
            "success",
            "Created refresh token and access token for user {} successfully".format(random_user_email),
            "register new user"
        )
        test_results.append(register_new_user)

        login_existent_user = test_login(
            random_user_email,
            random_user_password,
            "success",
            "Found valid refresh token for user {}".format(random_user_email),
            "login existent user"
        )
        test_results.append(login_existent_user)

        login_wrong_password = test_login(
            random_user_email,
            "definitelythewrongpassword",
            "error",
            "The provided password is incorrect",
            "login existent user with wrong password"
        )
        test_results.append(login_wrong_password)

        generate_existent_refresh = test_generate(
            login_existent_user['results']['refresh'],
            "success",
            "Generated a new access token",
            "generate access token for existent refresh token"
        )
        test_results.append(generate_existent_refresh)

        register_existent_user = test_register(
            random_user_email,
            random_user_password,
            "error",
            "A user already exists with this email",
            "register existent user"
        )
        test_results.append(register_existent_user)

        logout_existent_user = test_logout(
            login_existent_user['results']['access'],
            "success",
            "User was successfully logged out",
            "logout existent user"
        )
        test_results.append(logout_existent_user)

        login_no_refresh = test_login(
            random_user_email,
            random_user_password,
            "success",
            "Created refresh token and access token for user {} successfully".format(random_user_email),
            "login existent user with no valid refresh token"
        )
        test_results.append(login_no_refresh)

        update_only_email = test_update(
            login_existent_user['results']['access'],
            random_user_email_2,
            None,
            "success",
            "User information was successfully updated",
            "update existent user email only"
        )
        test_results.append(update_only_email)

        update_only_password = test_update(
            login_existent_user['results']['access'],
            None,
            random_user_password_2,
            "success",
            "User information was successfully updated",
            "update existent user password only"
        )
        test_results.append(update_only_password)

        update_email_password = test_update(
            login_existent_user['results']['access'],
            random_user_email_3,
            random_user_password_3,
            "success",
            "User information was successfully updated",
            "update existent user email and password"
        )
        test_results.append(update_email_password)

        login_updated_user = test_login(
            random_user_email_3,
            random_user_password_3,
            "success",
            "Found valid refresh token for user {}".format(random_user_email_3),
            "login existent user"
        )
        test_results.append(login_updated_user)

        login_old_creds = test_login(
            random_user_email,
            random_user_password,
            "error",
            "There is no active SportSim user with this email",
            "login updated user with old email and password"
        )
        test_results.append(login_old_creds)

        login_old_password = test_login(
            random_user_email_3,
            random_user_password,
            "error",
            "The provided password is incorrect",
            "login updated user with old password"
        )
        test_results.append(login_old_password)

        generate_updated_refresh = test_generate(
            login_updated_user['results']['refresh'],
            "success",
            "Generated a new access token",
            "generate access token for updated user"
        )
        test_results.append(generate_updated_refresh)

        deactivate_existent_user = test_deactivate(
            login_updated_user['results']['access'],
            "success",
            "User was successfully deactivated",
            "deactivate existent user"
        )
        test_results.append(deactivate_existent_user)

        login_inactive_user = test_login(
            random_user_email_3,
            random_user_password_3,
            "error",
            "There is no active SportSim user with this email",
            "login inactive user"
        )
        test_results.append(login_inactive_user)

        register_inactive_user = test_register(
            random_user_email_3,
            random_user_password_3,
            "error",
            "A user already exists with this email",
            "register inactive user"
        )
        test_results.append(register_inactive_user)

        generate_inactive_user = test_generate(
            login_updated_user['results']['refresh'],
            "error",
            "No valid refresh tokens match the provided token",
            "generate access token for inactive user"
        )
        test_results.append(generate_inactive_user)

        logout_inactive_user = test_logout(
            login_updated_user['results']['access'],
            "error",
            "No user found matching the provided id",
            "logout inactive user"
        )
        test_results.append(logout_inactive_user)

        deactivate_inactive_user = test_deactivate(
            login_updated_user['results']['access'],
            "error",
            "No user found matching the provided id",
            "deactivate existent user"
        )
        test_results.append(deactivate_inactive_user)
    except Exception as e:
        print("Tests failed during or following user creation due to error: {}".format(str(e)))
        return test_results

    return test_results

def report_results(discord_token, channel_id, results):
    #Format the report results message
    total_passed = 0
    total_failed = 0
    for result in results:
        if result['passed']:
            total_passed += 1
        else:
            total_failed += 1
    main_message          = ""
    if total_passed      >= 45:
        main_message     += ":white_check_mark: "
        embed_color       = 2067276
    elif total_passed    >= 30:
        main_message     += ":yellow_circle: "
        embed_color       = 12745742
    elif total_passed    >= 15:
        main_message     += ":orange_circle: "
        embed_color       = 11027200
    else:
        main_message     += ":x: "
        embed_color       = 10038562
    main_message         += "**User Service Test Results**:"
    embed                 = f"Total passed: {total_passed}, Total failed: {total_failed}"

    #Format the request body
    request_body = f'{{ \"content\":\"{main_message}\", \"embeds\": [{{ \"title\": \"Results\", \"description\": \"{embed}\", \"color\": {embed_color} }}] }}'

    #Create the message
    response = json.loads(subprocess.check_output(['curl', '-X', 'POST', '-H', f"Authorization: Bot {discord_token}", "-H", "Content-Type: application/json", '-d', request_body, f'https://discord.com/api/channels/{channel_id}/messages']))

    #Respond to the message in its thread with the individual results
    if 'id' in response.keys() and total_failed != 0:
        timestamp = datetime.now().strftime("%Y-%m-%d")
        request_body = f'{{ \"name\": \"{timestamp} User Service Test Results\" }}'
        response = json.loads(subprocess.check_output(['curl', '-X', 'POST', '-H', f"Authorization: Bot {discord_token}", "-H", "Content-Type: application/json", '-d', request_body, f'https://discord.com/api/channels/{channel_id}/messages/{response["id"]}/threads']))
        if 'id' in response.keys():
            for result in results:
                if not result['passed']:
                    request_body     = f'{{ \"content\": \"Result: {result["test"]}\", \"embeds\": [{{ \"title\": \"Results\", \"description\": \"Test {result["test"]} failed with results```{result["results"]}```\", \"color\": 10038562 }}] }}'
                    discord_response = json.loads(subprocess.check_output(['curl', '-X', 'POST', '-H', f"Authorization: Bot {discord_token}", "-H", "Content-Type: application/json", '-d', request_body, f'https://discord.com/api/channels/{response["id"]}/messages']))
                    print(discord_response)
        else:
            print(response)

def main():
    load_dotenv('./cronjobs/.env')
    discord_token = os.environ.get('DISCORD_BOT_TOKEN', '')
    channel_id    = os.environ.get('DISCORD_CHANNEL_ID', '')
    results       = test()
    report_results(discord_token, channel_id, results)
    

if __name__ == "__main__":
    main()