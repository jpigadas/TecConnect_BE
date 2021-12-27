from flask import jsonify

from init import app
from config import Config
from http_client import Client
import http_exception.error_handlers
from models.okta_user_config import CipherPlainText
from kms_envelop_encryption.encryption import encrypt_data
from helpers.route_helpers import authenticate_card_uid, update_configuration_for_user, get_payloads_and_validate, \
    credenti_config_v2, request_headers, get_base_url, get_authn_payloads


# # Authn API
@app.route('/api/v1/tectango/rfid/user/authn', methods=['POST'])
def authentication():
    try:
        print('Info :: In Authentication.')
        # # Parsing input JSON Data to variables.
        payloads = get_authn_payloads()
        if payloads is not None:
            card_uid = payloads.cardUID
            okta_tenant_url = payloads.oktaTenantUrl
            roaming_api_key, app_id, aws_kms_arn = credenti_config_v2(okta_tenant_url)
            if roaming_api_key is None:
                print('Error :: DynamoDB requested resource not found')
                return http_exception.error_handlers.AUTHN_DYNAMODB_EXCEPTION
            client_with_okta_tenant = Client(host=okta_tenant_url,
                                             request_headers=request_headers(roaming_api_key))
            # # Validating expected argument in JSON body. if key doesn't exist, returns None.
            print('Info :: Authenticating Card UID.')
            final_data, tectango_rfid_config_data, user_data = authenticate_card_uid(card_uid, payloads, client_with_okta_tenant, app_id, okta_tenant_url, aws_kms_arn)
            if final_data is None:
                return tectango_rfid_config_data
            else:
                # # return authorized cardUID user data.
                print('Info :: Authentication Success')
                return json.loads(final_data)
        else:
            print('Error :: Authentication request failed')
            return http_exception.error_handlers.AUTHN_REQUEST_NOT_VALID
    except Exception as e:
        print('Error :: Authentication failed')
        return http_exception.error_handlers.AUTHENTICATION_FAILED


# # Updating Last Login API
@app.route('/api/v1/tectango/rfid/user/authn/update/last_login_time', methods=['POST'])
def update_last_login_time():
    try:
        print('Info :: In Update last login time.')
        # # parsing input JSON Data to variables.
        payloads = get_authn_payloads()
        if payloads is not None:
            card_uid = payloads.cardUID
            last_login_time = payloads.last_login_time
            okta_tenant_url = payloads.oktaTenantUrl
            roaming_api_key, app_id, aws_kms_arn = credenti_config_v2(okta_tenant_url)
            if roaming_api_key is None:
                print('Error :: DynamoDB requested resource not found')
                return http_exception.error_handlers.AUTHN_DYNAMODB_EXCEPTION
            client_with_okta_tenant = Client(host=okta_tenant_url,
                                             request_headers=request_headers(roaming_api_key))
            # # validating expected argument in JSON body. if key doesn't exist, returns None.
            print("Info :: validating expected argument in JSON body. if key doesn't exist, returns None.")
            final_data, tectango_rfid_config_data, user_data = authenticate_card_uid(card_uid, payloads, client_with_okta_tenant, app_id, okta_tenant_url, aws_kms_arn)
            if final_data is None:
                return tectango_rfid_config_data
            else:
                previous_last_login_time_stamp = user_data.previous_last_login_time_stamp
                update_last_login_time_stamp = last_login_time
                updated_data = tectango_rfid_config_data.replace(previous_last_login_time_stamp,
                                                                 update_last_login_time_stamp)
                updated_data = json.loads(updated_data)
                # # Method to update Last Login Data
                update_last_login = update_configuration_for_user(updated_data, card_uid, app_id, client_with_okta_tenant,
                                              okta_tenant_url, None, user_data)
                if update_last_login is None:
                    print('Error :: Failed to Update of credentials to OKTA')
                    return http_exception.error_handlers.AUTHN_UPDATE_CREDENTIALS_FAILED
                if update_last_login is False:
                    print('Error :: Failed to store or update the cipher text in DynamoDB')
                    return http_exception.error_handlers.AUTHN_DYNAMODB_FAILED
                else:
                    print('Info :: Updated last login time.')
                    return updated_data
        else:
            print('Error :: Authentication Request Failed')
            return http_exception.error_handlers.AUTHN_REQUEST_NOT_VALID
    except Exception as e:
        print('Error :: Authentication failed')
        return http_exception.error_handlers.AUTHENTICATION_FAILED


@app.route('/api/v1/tectango/rfid/user/authn/update/profile', methods=['POST'])
def update_password():
    try:
        print('Info :: In update password.')
        # # parsing input JSON Data to variables.
        payloads = get_authn_payloads()
        if payloads is not None:
            payload = payloads.payload_data
            if payload.__contains__(Config.LAST_LOGIN_TIME):
                print('Info :: updating password as well as last login time')
                card_uid = payloads.cardUID
                last_login_time = payloads.last_login_time
                password = payloads.password
                okta_tenant_url = payloads.oktaTenantUrl
            else:
                print('Info :: updating only password')
                card_uid = payloads.cardUID
                password = payloads.password
                okta_tenant_url = payloads.oktaTenantUrl
            roaming_api_key, app_id, aws_kms_arn = credenti_config_v2(okta_tenant_url)
            if roaming_api_key is None:
                return http_exception.error_handlers.AUTHN_DYNAMODB_EXCEPTION
            client_with_okta_tenant = Client(host=okta_tenant_url,
                                             request_headers=request_headers(roaming_api_key))
            # # validating expected argument in JSON body. if key doesn't exist, returns None.
            print("Info :: validating expected argument in JSON body. if key doesn't exist, returns None.")
            final_data, tectango_rfid_config_data, user_data = authenticate_card_uid(card_uid, payloads,
                                                                                     client_with_okta_tenant, app_id,
                                                                                     okta_tenant_url, aws_kms_arn)
            if final_data is None:
                # # returns cardUID not found.
                print('Error :: CardUID not found.')
                return tectango_rfid_config_data
            else:
                tectango_rfid_config_in_dict = json.loads(tectango_rfid_config_data)
                if payload.__contains__(Config.LAST_LOGIN_TIME):
                    last_login_time = payloads.last_login_time
                    update_last_login_time_stamp = last_login_time

                    previous_last_login_time_stamp = user_data.previous_last_login_time_stamp
                    updated_last_login = tectango_rfid_config_data.replace(previous_last_login_time_stamp,
                                                                           update_last_login_time_stamp)
                    # # Encrypting Password using Envelop encryption.
                    # Generating Encrypted Password and cipher_text_blob_of_encrypted_password which help in decryption.
                    encrypted_password, cipher_text_blob_of_encrypted_password = encrypt_data(password, aws_kms_arn)
                    if encrypted_password is None:
                        return http_exception.error_handlers.AUTHN_ENCRYPTION_FAILED
                    CipherPlainText(cipher_text_blob_of_encrypted_password, None)
                    previous_password = user_data.profileKey
                    update_password = encrypted_password
                    updated_password = updated_last_login.replace(previous_password, update_password)
                    updated_password_data = json.loads(updated_password)
                    update_password_and_last_login = update_configuration_for_user(updated_password_data, card_uid, app_id, client_with_okta_tenant,
                                                  okta_tenant_url, Config.PROFILE_KEY, user_data)
                    if update_password_and_last_login is None:
                        print('Error :: Failed to Update of credentials to OKTA')
                        return http_exception.error_handlers.AUTHN_UPDATE_CREDENTIALS_FAILED
                    if update_password_and_last_login is False:
                        print('Error :: Failed to store or update the cipher text in DynamoDB')
                        return http_exception.error_handlers.AUTHN_DYNAMODB_FAILED
                    # return json.loads(tectango_rfid_config_in_dict)
                    else:
                        print('Info :: Updated password and last login time.')
                        return updated_password_data
                else:
                    encrypted_password, cipher_text_blob_of_encrypted_password = encrypt_data(password, aws_kms_arn)
                    if encrypted_password is None:
                        return http_exception.error_handlers.AUTHN_ENCRYPTION_FAILED
                    CipherPlainText(cipher_text_blob_of_encrypted_password, None)
                    previous_password = user_data.profileKey
                    update_password = encrypted_password
                    updated_password = tectango_rfid_config_data.replace(previous_password, update_password)
                    updated_password_data = json.loads(updated_password)
                    updating_password = update_configuration_for_user(updated_password_data, card_uid, app_id, client_with_okta_tenant,
                                                  okta_tenant_url, Config.PROFILE_KEY, user_data)
                    if updating_password is None:
                        print('Error :: Failed to Update of credentials to OKTA')
                        return http_exception.error_handlers.AUTHN_UPDATE_CREDENTIALS_FAILED
                    if updating_password is False:
                        print('Error :: Failed to store or update the cipher text in DynamoDB')
                        return http_exception.error_handlers.AUTHN_DYNAMODB_FAILED
                    print('Info :: Updated password')
                    return updated_password_data
        else:
            print('Error :: Authentication Request Failed')
            return http_exception.error_handlers.AUTHN_REQUEST_NOT_VALID
    except Exception as e:
        print('Error :: ', e)
        return http_exception.error_handlers.AUTHENTICATION_FAILED


@app.route('/api/v1/tectango/rfid/user/authn/update/pin', methods=['POST'])
def update_pin():
    try:
        print('Info :: In update pin.')
        # # parsing input JSON Data to variables.
        payloads = get_authn_payloads()
        if payloads is not None:
            card_uid = payloads.cardUID
            pin = payloads.pin
            okta_tenant_url = payloads.oktaTenantUrl
            roaming_api_key, app_id, aws_kms_arn = credenti_config_v2(okta_tenant_url)
            if roaming_api_key is None:
                return http_exception.error_handlers.AUTHN_DYNAMODB_EXCEPTION
            client_with_okta_tenant = Client(host=okta_tenant_url,
                                             request_headers=request_headers(roaming_api_key))
            # # validating expected argument in JSON body. if key doesn't exist, returns None.
            print("Info :: validating expected argument in JSON body. if key doesn't exist, returns None.")
            final_data, tectango_rfid_config_data, user_data = authenticate_card_uid(card_uid, payloads, client_with_okta_tenant, app_id, okta_tenant_url, aws_kms_arn)

            encrypted_pin, cipher_text_blob_of_pin = encrypt_data(pin, aws_kms_arn)
            if encrypted_pin is None:
                return http_exception.error_handlers.AUTHN_ENCRYPTION_FAILED
            CipherPlainText(cipher_text_blob_of_pin, None)


            if final_data is None:
                # # returns cardUID not found.
                print('Error :: CardUID not found.')
                return tectango_rfid_config_data
            else:
                tectango_rfid_config_in_dict = json.loads(tectango_rfid_config_data)
                tectango_rfid_config_in_dict['_embeddedData']['user']['profile']['profileCode'] = encrypted_pin
                updating_pin = update_configuration_for_user(tectango_rfid_config_in_dict, card_uid, app_id, client_with_okta_tenant,
                                              okta_tenant_url, Config.PROFILE_CODE, user_data)
                if updating_pin is None:
                    print('Error :: Failed to Update of credentials to OKTA')
                    return http_exception.error_handlers.AUTHN_UPDATE_CREDENTIALS_FAILED
                if updating_pin is False:
                    print('Error :: Failed to store or update the cipher text in DynamoDB')
                    return http_exception.error_handlers.AUTHN_DYNAMODB_FAILED
                # return json.loads(tectango_rfid_config_in_dict)
                print('Info :: Pin updated')
                return tectango_rfid_config_in_dict
        else:
            print('Error :: Authentication Request Failed')
            return http_exception.error_handlers.AUTHN_REQUEST_NOT_VALID
    except Exception as e:
        print('Error :: ', e)
        return http_exception.error_handlers.AUTHENTICATION_FAILED


from http_exception.error_handlers import *















# username = tectango_rfid_config_in_dict['_embeddedData']['user']['profile']['samAccountName']
# user_id = tectango_rfid_config_in_dict['_embeddedData']['user']['profile']['userID']

# authn_blueprint = Blueprint("authn_blueprint", __name__)

# # Exceptions # #

# # Authentication Failed
# # Authentication Request Failed
# # CardUID Not Found

#
# @app.route('/api/v1/tectango/rfid/user/authn/update/password/lastlogin', methods=['POST'])
# def update_password_and_last_login():
#     try:
#         # # parsing input JSON Data to variables.
#         payload = get_payloads_and_validate()
#         if payload is not None:
#             #if tectango_rfid_config_data.__contains__("_embeddedData"):
#             card_uid = payload.get('cardUID')
#             last_login_time = payload.get('last_login_time')
#             password = payload.get('password')
#             # # validating expected argument in JSON body. if key doesn't exist, returns None.
#             # # final_data, tectango_rfid_config_data = validate_card_uid_for_last_login(card_uid)
#             final_data, tectango_rfid_config_data = authenticate_card_uid(card_uid, payload)
#             if final_data is None:
#                 # # returns cardUID not found.
#                 return tectango_rfid_config_data
#             else:
#                 tectango_rfid_config_in_dict = json.loads(tectango_rfid_config_data)
#                 # username = tectango_rfid_config_in_dict['_embeddedData']['user']['profile']['samAccountName']
#                 # user_id = tectango_rfid_config_in_dict['_embeddedData']['user']['profile']['userID']
#                 last_login_time = payload.get('last_login_time')
#                 update_last_login_time_stamp = last_login_time
#                 previous_last_login_time_stamp = \
#                 tectango_rfid_config_in_dict['_embeddedData']['user']['lastLoginInfo'][
#                     'lastLoginTimeStamp']
#                 updated_last_login = json.dumps(tectango_rfid_config_data).replace(previous_last_login_time_stamp,
#                                                                                    update_last_login_time_stamp)
#                 # # Encrypting Password using Envelop encryption.
#                 # Generating Encrypted Password and cipher_text_blob_of_encrypted_password which help in decryption.
#                 encrypted_password, cipher_text_blob_of_encrypted_password = encrypt_data(password)
#                 # print("encrypted_password:", encrypted_password)
#                 # print("cipher_text_blob_of_encrypted_password:", cipher_text_blob_of_encrypted_password)
#                 previous_password = tectango_rfid_config_in_dict['_embeddedData']['user']['profile'][
#                     'secret']
#                 update_password = encrypted_password
#                 updated_password = updated_last_login.replace(previous_password, update_password)
#
#                 previous_cipher_text_blob = tectango_rfid_config_in_dict['_embeddedData']['user']['cipherTextBlob'][
#                     'secret']
#                 update_cipher_text_blob = cipher_text_blob_of_encrypted_password
#                 updated_cipher_text_blob = updated_password.replace(previous_cipher_text_blob, update_cipher_text_blob)
#                 # # Method to update Last Login Data
#                 updated_cipher_text_blob_json = json.loads(json.loads(updated_cipher_text_blob))
#                 update_configuration_for_user(updated_cipher_text_blob_json, card_uid)
#                 #return json.loads(tectango_rfid_config_in_dict)
#                 return updated_cipher_text_blob_json
#         else:
#             #return http_exception.error_handlers.AUTHENTICATION_REQUEST_FAILED
#             return "Authentication Request Failed"
#     except Exception as e:
#         print(e)
#         #return http_exception.error_handlers.AUTHENTICATION_FAILED
#         return "Authentication Failed"
#
#
# @app.route('/api/v1/tectango/rfid/user/authn/update/password', methods=['POST'])
# def update_password():
#     try:
#         # # parsing input JSON Data to variables.
#         payload = get_payloads_and_validate()
#         if payload is not None:
#             card_uid = payload.get('cardUID')
#             password = payload.get('password')
#             # # validating expected argument in JSON body. if key doesn't exist, returns None.
#             # # final_data, tectango_rfid_config_data = validate_card_uid_for_last_login(card_uid)
#             final_data, tectango_rfid_config_data = authenticate_card_uid(card_uid, payload)
#             if final_data is None:
#                 # # returns cardUID not found.
#                 return tectango_rfid_config_data
#             else:
#                 tectango_rfid_config_in_dict = json.loads(tectango_rfid_config_data)
#                 # # Encrypting Password using Envelop encryption.
#                 # Generating Encrypted Password and cipher_text_blob_of_encrypted_password which help in decryption.
#                 encrypted_password, cipher_text_blob_of_encrypted_password = encrypt_data(password)
#                 # print("encrypted_password:", encrypted_password)
#                 # print("cipher_text_blob_of_encrypted_password:", cipher_text_blob_of_encrypted_password)
#                 previous_password = tectango_rfid_config_in_dict['_embeddedData']['user']['profile'][
#                     'secret']
#                 update_password = encrypted_password
#                 updated_password = json.dumps(tectango_rfid_config_data).replace(previous_password, update_password)
#
#                 previous_cipher_text_blob = tectango_rfid_config_in_dict['_embeddedData']['user']['cipherTextBlob'][
#                     'secret']
#                 update_cipher_text_blob = cipher_text_blob_of_encrypted_password
#                 updated_cipher_text_blob = updated_password.replace(previous_cipher_text_blob,
#                                                                     update_cipher_text_blob)
#                 # # Method to update Last Login Data
#                 updated_cipher_text_blob_json = json.loads(json.loads(updated_cipher_text_blob))
#                 update_configuration_for_user(updated_cipher_text_blob_json, card_uid)
#                 # return json.loads(tectango_rfid_config_in_dict)
#                 return updated_cipher_text_blob_json
#         else:
#             # return http_exception.error_handlers.AUTHENTICATION_REQUEST_FAILED
#             return "Authentication Request Failed"
#     except Exception as e:
#         print(e)
#         # return http_exception.error_handlers.AUTHENTICATION_FAILED
#         return "Authentication Failed"
#
#
# from http_exception.error_handlers import *


# @app.route('/tectango/rfid/v1/user/authn/update/password', methods=['POST'])
# def update_password():
#     try:
#         # # parsing input JSON Data to variables.
#         payload = get_payloads_and_validate()
#         if payload is not None:
#             card_uid = payload.get('cardUIDs')
#             last_login_time = payload.get('last_login_time')
#             password = payload.get('password')
#             # # validating expected argument in JSON body. if key doesn't exist, returns None.
#             # # final_data, tectango_rfid_config_data = validate_card_uid_for_last_login(card_uid)
#             final_data, tectango_rfid_config_data = authenticate_card_uid(card_uid, payload)
#             if final_data is None:
#                 # # returns cardUID not found.
#                 return tectango_rfid_config_data
#             else:
#                 tectango_rfid_config_in_dict = json.loads(tectango_rfid_config_data)
#                 # username = tectango_rfid_config_in_dict['_embeddedData']['user']['profile']['samAccountName']
#                 # user_id = tectango_rfid_config_in_dict['_embeddedData']['user']['profile']['userID']
#                 previous_last_login_time_stamp = tectango_rfid_config_in_dict['_embeddedData']['user']['lastLoginInfo'][
#                     'lastLoginTimeStamp']
#                 update_last_login_time_stamp = last_login_time
#
#                 updated_last_login = json.dumps(tectango_rfid_config_data).replace(previous_last_login_time_stamp,
#                                                                                    update_last_login_time_stamp)
#                 # # Encrypting Password using Envelop encryption.
#                 # Generating Encrypted Password and cipher_text_blob_of_encrypted_password which help in decryption.
#                 encrypted_password, cipher_text_blob_of_encrypted_password = encrypt_data(password)
#                 # print("encrypted_password:", encrypted_password)
#                 # print("cipher_text_blob_of_encrypted_password:", cipher_text_blob_of_encrypted_password)
#                 previous_password = tectango_rfid_config_in_dict['_embeddedData']['user']['profile'][
#                     'secret']
#                 update_password = encrypted_password
#                 updated_password = updated_last_login.replace(previous_password, update_password)
#
#                 previous_cipher_text_blob = tectango_rfid_config_in_dict['_embeddedData']['user']['cipherTextBlob'][
#                     'secret']
#                 update_cipher_text_blob = cipher_text_blob_of_encrypted_password
#                 updated_cipher_text_blob = updated_password.replace(previous_cipher_text_blob, update_cipher_text_blob)
#                 # # Method to update Last Login Data
#                 updated_cipher_text_blob_json = json.loads(json.loads(updated_cipher_text_blob))
#                 update_configuration_for_user(updated_cipher_text_blob_json, card_uid)
#                 #return json.loads(tectango_rfid_config_in_dict)
#                 return updated_cipher_text_blob_json
#         else:
#             #return http_exception.error_handlers.AUTHENTICATION_REQUEST_FAILED
#             return "Authentication Request Failed"
#     except Exception as e:
#         print(e)
#         #return http_exception.error_handlers.AUTHENTICATION_FAILED
#         return "Authentication Failed"
