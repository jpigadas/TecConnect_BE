from init import app
from config import Config
from http_client import Client
import http_exception.error_handlers
from models.okta_user_config import CipherPlainText
from validations.json_format import enrollment_data
from kms_envelop_encryption.encryption import encrypt_data
from helpers.route_helpers import update_configuration_for_user, update_offline_data, request_headers, credenti_config_v2, validate_payloads, validate_card_uid


# # welcome API
@app.route('/api/v1/tectango')
def welcome():
    return 'Welcome to TecTANGO EnrollmentMS!'


# # Enrollment API
@app.route('/api/v1/tectango/rfid/enroll/primary', methods=['POST'])
def primary_enrollment():
    try:
        print('Info :: In primary enrollment.')
        payloads = validate_payloads()
        if payloads is None:
            print('Error :: Received Invalid JSON payload')
            return http_exception.error_handlers.ENROLL_REQUEST_NOT_VALID
        username = payloads.username
        card_uid = payloads.cardUID
        okta_tenant_url = payloads.oktaTenantUrl
        # # Retrieves the template application credentials from DynamoDB table.
        roaming_api_key, app_id, aws_kms_arn = credenti_config_v2(okta_tenant_url)
        if roaming_api_key is None:
            print('Error :: DynamoDB requested resource not found')
            return http_exception.error_handlers.ENROLL_DYNAMODB_EXCEPTION
        # Api end point to get user ID by exchanging username
        # {url}}/api/v1/users/{{userName}}
        print('Info :: Getting user response by making internal API call to OKTA')
        client_with_okta_tenant = Client(host=okta_tenant_url,
                                         request_headers=request_headers(roaming_api_key))
        try:
            response = client_with_okta_tenant.api.v1.users._(username).get()
        except Exception as e:
            print('Error :: User not found')
            return http_exception.error_handlers.ENROLL_NOT_FOUND_EXCEPTION
        print('Info :: Creating JSON Enrollment data to store it in OKTA.')
        enrollment_json_stored_in_okta, user = enrollment_data(payloads, response, aws_kms_arn)
        if enrollment_json_stored_in_okta is None:
            print('Error :: Marshmallow Validation Failed')
            return http_exception.error_handlers.Enroll_Marshmallow_JSON_Formation_Failed
        if enrollment_json_stored_in_okta is False:
            print('Error :: Envelop Encryption Failed')
            return http_exception.error_handlers.ENROLL_ENCRYPTION_FAILED
        # Updating user config data in OKTA
        enrollment_response_in_plaintext = update_configuration_for_user(enrollment_json_stored_in_okta, card_uid,
                                                                         app_id, client_with_okta_tenant, okta_tenant_url, Config.PROFILE_KEY, user)
        if enrollment_response_in_plaintext is None:
            print('Error :: Invalid client app id or User id')
            return http_exception.error_handlers.ENROLL_UPDATE_CREDENTIALS_FAILED
        if enrollment_response_in_plaintext is False:
            print('Error :: Failed to store or update the cipher text data in DynamoDB')
            return http_exception.error_handlers.ENROLL_DYNAMODB_FAILED
        else:
            print('Info :: User Successfully Enrolled')
            return http_exception.error_handlers.USER_SUCCESSFULLY_ENROLLED
    except Exception as e:
        print("Error :: Enrollment failed")
        return http_exception.error_handlers.ENROLLMENT_FAILED


# # Dynamically adding offline data structure and storing it in OKTA
# # Offline Enrollment Factor API
@app.route('/api/v1/tectango/rfid/offline/enroll', methods=['POST'])
def offline_enrollment():
    try:
        print('Info :: In Offline enrollment.')
        payloads = validate_payloads()
        if payloads is None:
            return http_exception.error_handlers.ENROLL_REQUEST_NOT_VALID
        # # Get the configuration from JSON POST
        card_uid = payloads.cardUID
        offline_profile_key = payloads.secretKey
        factor_type = payloads.factorType
        okta_tenant_url = payloads.oktaTenantUrl
        # # Retrieves the template application credentials from DynamoDB table.
        roaming_api_key, app_id, aws_kms_arn = credenti_config_v2(okta_tenant_url)
        if roaming_api_key is None:
            return http_exception.error_handlers.ENROLL_DYNAMODB_EXCEPTION
        print('Info :: Getting Enrolled user data from OKTA')
        client_with_okta_tenant = Client(host=okta_tenant_url,
                                         request_headers=request_headers(roaming_api_key))
        user = validate_card_uid(card_uid, client_with_okta_tenant, app_id)
        if user is None:
            print("Error :: Card UID not found.")
            return http_exception.error_handlers.ENROLL_CARD_UID_NOT_FOUND

        user_data = user.user_data
        tectango_rfid_config_in_dict = user.tectango_rfid_config
        print('Info :: Encrypting Offline SecretKey using Envelop encryption.')
        encrypted_secret_key, cipher_text_blob_of_encrypted_secret_key = encrypt_data(offline_profile_key, aws_kms_arn)
        if encrypted_secret_key is None:
            print('Error :: Envelop Encryption Failed')
            return http_exception.error_handlers.ENROLL_ENCRYPTION_FAILED
        CipherPlainText(cipher_text_blob_of_encrypted_secret_key, None)
        if user_data.__contains__(Config.OFFLINE):
            # # Updating Offline Data to the Response
            print('Info :: Updating Offline Enrollment Data to the user data.')
            offline_added_data = update_offline_data(user, user_data, tectango_rfid_config_in_dict, card_uid, factor_type,
                                                     app_id,
                                                     client_with_okta_tenant, encrypted_secret_key, okta_tenant_url,
                                                     cipher_text_blob_of_encrypted_secret_key)
            if offline_added_data is None:
                return http_exception.error_handlers.ENROLL_UNSUPPORTED_FACTOR_TYPE
            else:
                print('Info :: Offline Enrollment Success.')
                return offline_added_data
        else:
            # # Constructing Offline Key Structure for the first time.
            print('Info :: Constructing Offline Key Structure for the first time.')
            offline_key_structure1 = {"offline": {"factors": {}}}
            user_data.update(offline_key_structure1)
            # # Updating Offline Data to the Response
            print('Info :: Updating Offline Enrollment Data to the user data.')
            offline_added_data = update_offline_data(user, user_data, tectango_rfid_config_in_dict, card_uid,
                                                     factor_type, app_id,
                                                     client_with_okta_tenant, encrypted_secret_key,
                                                     okta_tenant_url, cipher_text_blob_of_encrypted_secret_key)

            print('Info :: Offline Enrollment Success.')
            return offline_added_data
    except Exception as e:
        print('Error :: ', e)
        return http_exception.error_handlers.ENROLLMENT_FAILED


#from http_exception.error_handlers import *






















#
# from helpers import route_helpers
# from http_client import Client
# from init import app
# from config import Config
# from flask import request
# import http_exception.error_handlers
# from validations.json_format import enrollment_data
# from kms_envelop_encryption.encryption import encrypt_data
# from validations.Payload_Validation import primary_enroll_data_validation, offline_enroll_data_validation
# from helpers.route_helpers import update_configuration_for_user, get_payloads, \
#     create_cipher_text_blob_structure, update_offline_data, request_headers, client, credenti_config_v1
#
# from urllib.parse import urlparse
#
# # # welcome API
# @app.route('/api/v1/tectango')
# def welcome():
#     host_name = urlparse(request.base_url)
#     return str(host_name.netloc)
#     #return 'Welcome to TecAdmin Console EnrollmentMS!'
#
#
# # # Enrollment API
# @app.route('/api/v1/tectango/rfid/enroll/primary', methods=['POST'])
# def primary_enrollment():
#     try:
#         host_name = urlparse(request.base_url)
#         base_url = host_name.netloc
#         okta_tenant_url, roaming_api_key, app_id = credenti_config_v1("mountsinai.credenti.xyz")
#         #Config("mountsinai.credenti.xyz")
#         print('Info :: In primary enrollment.')
#         payload = request.json
#         # # calling validation function by passing payload
#         primary_enroll_data_validity = primary_enroll_data_validation(payload)
#         if not primary_enroll_data_validity:
#             print('Error :: The request body was not well-formed (or) Invalid data entered..')
#             return http_exception.error_handlers.INVALID_DATA_ENTERED
#         username = payload.get('username')
#         cardUID = payload.get('cardUID')
#         # Api end point to get user ID by exchanging username
#         # {url}}/api/v1/users/{{userName}}
#         client_with_okta_tenant = Client(host=okta_tenant_url,
#                                          request_headers=request_headers(roaming_api_key))
#         print('Info :: In getting user response by making internal API call to OKTA')
#         response = client_with_okta_tenant.api.v1.users._(username).get()
#         enrollment_json_stored_in_okta = enrollment_data(payload, response)
#         print('Info :: In forming Enrollment JSON data to store in OKTA.')
#         if enrollment_json_stored_in_okta is False:
#             print('Error :: Enrollment json formation failed through Marshmallow')
#             return http_exception.error_handlers.Marshmallow_JSON_Formation_Failed
#
#         enrollment_response_in_plaintext = update_configuration_for_user(enrollment_json_stored_in_okta, cardUID)
#         if enrollment_response_in_plaintext:
#             print('Info :: User Successfully Enrolled')
#             return http_exception.error_handlers.USER_SUCCESSFULLY_ENROLLED
#     except Exception as e:
#         print("Error :: ", e)
#         return http_exception.error_handlers.ENROLLMENT_FAILED
#
#
# # # Dynamically adding offline data structure and storing it in OKTA
# # # Offline Enrollment Factor API
# @app.route('/api/v1/tectango/rfid/offline/enroll', methods=['POST'])
# def offline_enrollment():
#     try:
#         host_name = urlparse(request.base_url)
#         base_url = host_name.netloc
#         okta_tenant_url, roaming_api_key, app_id = credenti_config_v1("mountsinai.credenti.xyz")
#         print('Info :: In Offline enrollment.')
#         # # Get the configurations from JSON POST
#         # # parsing input JSON Data to variables.
#         payloads = get_payloads()
#         offline_enroll_data_validity = offline_enroll_data_validation(payloads)
#         if not offline_enroll_data_validity:
#             print('Error :: The request body was not well-formed (or) Invalid data entered.')
#             return http_exception.error_handlers.INVALID_DATA_ENTERED
#
#         # # Get the configuration from JSON POST
#         card_uid = payloads.get('cardUID')
#         secret_key = payloads.get('secretKey')
#         factor_type = payloads.get('factorType')
#         print('Info :: getting Enrolled user data from OKTA.')
#         client_with_okta_tenant = Client(host=okta_tenant_url,
#                                          request_headers=request_headers(roaming_api_key))
#         response = client_with_okta_tenant.api.v1.apps._(Config.app_id).users.get()
#         users = response.to_dict
#         for user in users:
#             # # Validating given cardUID with the enrolled cardUID users in Response from OKTA.
#             if user['profile']['cardUID'] == card_uid:
#                 print('Info :: Card UID matched with the user response from OKTA.')
#                 tectango_rfid_config = user['profile']['tectangoRFIDConfig']
#                 tectango_rfid_config_in_dict = json.loads(tectango_rfid_config)
#                 user_data = tectango_rfid_config_in_dict['_embeddedData']
#
#                 cipher_text_blob = tectango_rfid_config_in_dict['_embeddedData']['user']['cipherTextBlob']
#                 append_offline_secret_key_with_cipher_text_blob = cipher_text_blob
#
#                 # # Encrypting Offline SecretKey using Envelop encryption.
#                 # # Storing encrypted_secret_key and cipher_text_blob of SecretKey which help in decryption.
#                 print('Info :: Encrypting Offline SecretKey using Envelop encryption.')
#                 encrypted_secret_key, cipher_text_blob_of_encrypted_secret_key = encrypt_data(secret_key)
#                 # # Appending CipherTextBlob of SecretKey with FactorType in Response.
#                 append_offline_secret_key_with_cipher_text_blob.update(
#                     create_cipher_text_blob_structure(factor_type, cipher_text_blob_of_encrypted_secret_key))
#
#                 if user_data.__contains__('offline'):
#                     # # Updating Offline Data to the Response
#                     print('Info :: Updating Offline Enrollment Data to the user data.')
#                     offline_added_data = update_offline_data(user_data, tectango_rfid_config_in_dict,
#                                                              card_uid, encrypted_secret_key, factor_type)
#                     return offline_added_data
#                 else:
#                     # # Constructing Offline Key Structure for the first time.
#                     print('Info :: Constructing Offline Key Structure for the first time.')
#                     offline_key_structure1 = {"offline": {"factors": {}}}
#                     user_data.update(offline_key_structure1)
#
#                     # # Updating Offline Data to the Response
#                     print('Info :: Updating Offline Enrollment Data to the user data.')
#                     offline_added_data = update_offline_data(user_data, tectango_rfid_config_in_dict,
#                                                              card_uid, encrypted_secret_key, factor_type)
#                     print('Info :: Offline Enrollment Success.')
#                     return offline_added_data
#         else:
#             print('Error :: CardUID not found.')
#             return http_exception.error_handlers.CARD_UID_NOT_FOUND
#     except Exception as e:
#         print('Error :: ', e)
#         return http_exception.error_handlers.ENROLLMENT_FAILED
#
#
# from http_exception.error_handlers import *


# from urllib.parse import urlparse
# host_name = urlparse(request.base_url)
# print(str(host_name))
# import socket
#
# hostname = socket.gethostname()
# IPAddr = socket.gethostbyname(hostname)
# print("Your Computer Name is:" + hostname)
# print("Your Computer IP Address is:" + IPAddr)