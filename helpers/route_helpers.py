import json
import boto3
from flask import request
from urllib.parse import urlparse
import http_exception.error_handlers
from config import Config, CipherTxtBlob
from http_client.http_request import Client
from kms_envelop_encryption.decryption import decrypt_attribute
from models.okta_user_config import UserProfile, CipherPlainText
from validations.Payload_Validation import authn_payload_data_validation, offline_enroll_data_validation, \
    primary_enroll_data_validation


def request_headers(roaming_api_key):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": 'SSWS {}'.format(roaming_api_key)
    }
    return headers


def validate_payloads():
    # get input payload JSON data.
    payload = request.json
    if payload.__contains__(Config.FACTOR_TYPE):
        payloads = offline_enroll_data_validation(payload)
    else:
        payloads = primary_enroll_data_validation(payload)
    return payloads

def get_authn_payloads():
    payload = request.json
    payloads = authn_payload_data_validation(payload)
    return payloads


def credenti_config_v2(tenant_url):
    try:
        dynamodb = boto3.resource(Config.DYNAMODB, region_name=Config.REGION)
        table = dynamodb.Table(Config.DYNAMODB_TABLE_NAME)
        response = table.get_item(Key={Config.CUST_IDP_TENANT: tenant_url, Config.PRODUCT_SORT_KEY: Config.PRODUCT_TECTANGO})
        config_data = response['Item']
        roaming_api_key = config_data['idp_tectango_roaming_api_key']
        app_id = config_data['idp_oidc_tectango_roaming_app_id']
        aws_kms_arn = config_data['aws_kms_arn']
        return roaming_api_key, app_id, aws_kms_arn
    except Exception as e:
        return None, None, None


def update_configuration_for_user(enrollment_info, card_uid, okta_app_id, client_with_okta_tenant, okta_tenant_url, cipher_plain_text_key, user):
    user_id = user.user_id
    username = user.user_name
    print('Info :: Updating credentials in Okta for the user id: ', user_id, 'in app id:', okta_app_id)
    data = {
        "profile": {
            "userName": username,
            "cardUID": card_uid,
            "tectangoRFIDConfig": json.dumps(enrollment_info)
        }
    }
    # Api end point to update app profile attributes
    # {{url}}/api/v1/apps/{{appId}}/users/{{userId}}
    try:
        response = client_with_okta_tenant.api.v1.apps._(okta_app_id).users._(user_id).post(request_body=data)
        payload = request.json
        if not payload.__contains__(Config.USER_NAME) and cipher_plain_text_key is not None:
            updating_cipher_txt = update_cipher_txt_blob(okta_tenant_url, user_id, cipher_plain_text_key, CipherPlainText.cipher_text_blob_of_encrypted_password)
            if updating_cipher_txt is None:
                return False
        if payload.__contains__(Config.USER_NAME):
            storing_cipher_txt = store_cipher_txt_blob(okta_tenant_url, user_id, card_uid, cipher_plain_text_key, Config.PROFILE_CODE, CipherPlainText.cipher_text_blob_of_encrypted_password, CipherPlainText.cipher_text_blob_of_pin)
            if storing_cipher_txt is None:
                user_in_okta = validate_card_uid(card_uid, client_with_okta_tenant, okta_app_id)
                if user_in_okta is not None:
                    delete_user_in_okta(client_with_okta_tenant, okta_app_id, user_id)
                return False
        return response.body
    except Exception as e:
        return None


def delete_user_in_okta(client_with_okta_tenant, okta_app_id, user_id):
    # Api end point to delete user app profile
    # {{url}}/api/v1/apps/{{appId}}/users/{{userId}}
    response = client_with_okta_tenant.api.v1.apps._(okta_app_id).users._(user_id).delete()
    print("Response: ", response.status_code)


def get_base_url():
    host_name = urlparse(request.base_url)
    base_url = host_name.netloc
    return base_url


def get_client_with_okta_tenant(okta_tenant_url, roaming_api_key):
    client = Client(host=okta_tenant_url, request_headers=request_headers(roaming_api_key))
    return client


def get_payloads_and_validate():
    payload = request.json
    payload_data_validity = authn_payload_data_validation(payload)
    if not payload_data_validity:
        return None
    return payload


def get_payloads():
    # # get input payload JSON data.
    payload = request.json
    return payload


def authenticate_card_uid(card_uid, payload, client_with_okta_tenant, okta_app_id, okta_tenant_url, aws_kms_arn):
    payloads = payload.payload_data
    # # Validating cardUID
    user_data = validate_card_uid(card_uid, client_with_okta_tenant, okta_app_id)
    if user_data is None:
        print('Error :: Card UID not found')
        return None, http_exception.error_handlers.AUTHN_CARD_UID_NOT_FOUND, None
    tectango_rfid_config_data = json.dumps(user_data.tectango_rfid_config)
    if tectango_rfid_config_data.__contains__(Config.EMBEDDED_DATA):
        encrypted_password = user_data.profileKey
        encrypted_pin = user_data.profileCode
        user_id = user_data.user_id
        cipher_profile_key, cipher_profile_code = get_cipher_txt_blob(okta_tenant_url, user_id, Config.PROFILE_KEY, Config.PROFILE_CODE)
        if cipher_profile_key is None:
            print('Error :: Failed to get cipher text blob from DynamoDB')
            return None, http_exception.error_handlers.AUTHN_GET_CIPHER_TEXT_BLOB_FAILED, None
        print('Info :: Decrypting Password')
        decrypted_password = decrypt_attribute(encrypted_password, cipher_profile_key, aws_kms_arn)
        if decrypted_password is None:
            print('Error :: Envelop Decryption Failed')
            return None, http_exception.error_handlers.AUTHN_DECRYPTION_FAILED, None

        if tectango_rfid_config_data.__contains__(Config.OFFLINE):
            offline_enrolled_factors = user_data.offline_enrolled_factors
            if offline_enrolled_factors.__contains__(Config.U2F):
                encrypted_offline_u2f_secret_key = user_data.encrypted_offline_u2f_secret_key
                cipher_u2f_blob, cipher_profile_code = get_cipher_txt_blob(okta_tenant_url, user_id, Config.U2F, Config.PROFILE_CODE)
                if cipher_u2f_blob is None:
                    print('Error :: Failed to get cipher text blob from DynamoDB')
                    return None, http_exception.error_handlers.AUTHN_GET_CIPHER_TEXT_BLOB_FAILED, None
                print('Info :: Decrypting Offline U2F Security Key')
                decrypted_offline_u2f_secret_key = decrypt_attribute(encrypted_offline_u2f_secret_key, cipher_u2f_blob, aws_kms_arn)
                if decrypted_offline_u2f_secret_key is None:
                    print('Error :: Envelop Decryption Failed')
                    return None, http_exception.error_handlers.AUTHN_DECRYPTION_FAILED, None
                if not (payloads.__contains__(Config.LAST_LOGIN_TIME) or payloads.__contains__(
                        Config.PASSWORD) or payloads.__contains__(Config.PIN)):
                    tectango_rfid_config_data = tectango_rfid_config_data.replace(encrypted_offline_u2f_secret_key,
                                                                                  decrypted_offline_u2f_secret_key)
            if offline_enrolled_factors.__contains__(Config.OFFLINE_TOTP):
                encrypted_offline_totp_secret_key = user_data.encrypted_offline_totp_secret_key
                cipher_offlineTOTP_blob, cipher_profile_code = get_cipher_txt_blob(okta_tenant_url, user_id, Config.OFFLINE_TOTP ,Config.PROFILE_CODE)
                if cipher_offlineTOTP_blob is None:
                    print('Error :: Failed to get cipher text blob from DynamoDB')
                    return None, http_exception.error_handlers.AUTHN_GET_CIPHER_TEXT_BLOB_FAILED, None
                print('Info :: Decrypting Offline TOTP Security Key')
                decrypted_offline_totp_secret_key = decrypt_attribute(encrypted_offline_totp_secret_key, cipher_offlineTOTP_blob, aws_kms_arn)
                if decrypted_offline_totp_secret_key is None:
                    print('Error :: Envelop Decryption Failed')
                    return None, http_exception.error_handlers.AUTHN_DECRYPTION_FAILED, None

                if not (payloads.__contains__(Config.LAST_LOGIN_TIME) or payloads.__contains__(
                        Config.PASSWORD) or payloads.__contains__(Config.PIN)):
                    tectango_rfid_config_data = tectango_rfid_config_data.replace(encrypted_offline_totp_secret_key,
                                                                                  decrypted_offline_totp_secret_key)

        # #if len(payload) == 1:
        global decrypted_pin
        if encrypted_pin is not None:
            print('Info :: Decrypting PIN')
            decrypted_pin = decrypt_attribute(encrypted_pin, cipher_profile_code, aws_kms_arn)
            final_data = tectango_rfid_config_data.replace(encrypted_password, decrypted_password).replace(
                encrypted_pin, decrypted_pin)
            if decrypted_pin is None:
                print('Error :: Envelop Decryption Failed')
                return None, http_exception.error_handlers.AUTHN_DECRYPTION_FAILED, None
        else:
            final_data = tectango_rfid_config_data.replace(encrypted_password, decrypted_password)
        return final_data, tectango_rfid_config_data, user_data
    else:
        return None, tectango_rfid_config_data, None


def validate_card_uid(card_uid, client_with_okta_tenant, okta_app_id):
    # client = Client(host=Config.host, request_headers=request_headers)
    response = client_with_okta_tenant.api.v1.apps._(okta_app_id).users.get()
    users = response.to_dict
    for user in users:
        # # Validating given cardUID with the enrolled cardUID users in Response from OKTA.
        if user['profile']['cardUID'] == card_uid:
            print('Info :: Card UID found')
            user = json.dumps(user)
            user = UserProfile(user)
            return user
    else:
        return None


def create_offline_data(factor_type, secret_key):
    offline_data = {
        factor_type: {
            Config.OFFLINE_PROFILE_KEY: secret_key
        }
    }
    return offline_data


def create_cipher_text_blob_structure(factor_type, secret_key):
    offline_cipher_text_blob = {
        factor_type: secret_key
    }
    return offline_cipher_text_blob


# # Updating Offline Data to the Response
def update_offline_data(user, user_data, tectango_rfid_config_in_dict, card_uid, factor_type, okta_app_id,
                        client_with_okta_tenant, encrypted_secret_key, okta_tenant_url, cipher_plain_text):
    offline_factor = user_data['offline']['factors']
    # # TecTANGO supports U2F and offlineTOTP Factors
    if factor_type == Config.U2F or factor_type == Config.OFFLINE_TOTP:
        offline_factor.update(create_offline_data(factor_type, encrypted_secret_key))
        tectango_rfid_config_in_dict['_embeddedData'] = user_data
        update_offline_data  = update_configuration_for_user(tectango_rfid_config_in_dict, card_uid, okta_app_id, client_with_okta_tenant, okta_tenant_url, factor_type, user)
        if update_offline_data is None:
            print('Error :: Invalid client app id or User id')
            return http_exception.error_handlers.ENROLL_UPDATE_CREDENTIALS_FAILED
        if update_offline_data is False:
            print('Error :: Failed to store or update the cipher text in DynamoDB')
            return http_exception.error_handlers.ENROLL_DYNAMODB_FAILED
        return tectango_rfid_config_in_dict
    else:
        print('Error :: Unsupported factor type.')
        return None



def store_cipher_txt_blob(okta_tenant_url, user_id, card_uid, cipher_profile_key, cipher_profile_code, cipher_profile_key_blob, cipher_profile_code_blob):
    try:
        response = CipherTxtBlob.client.put_item(
            Item={
                Config.CUST_IDP_TENANT: {
                    "S": okta_tenant_url
                },
                Config.CIPHER_SORT_KEY: {
                    "S": user_id
                },
                Config.CARD_UID: {
                    "S": card_uid
                },
                cipher_profile_key: {
                    "S": cipher_profile_key_blob
                },
                cipher_profile_code: {
                    "S": cipher_profile_code_blob
                }
            },
            TableName=Config.CIPHER_TBL_NAME,
        )
        return True
    except Exception as e:
        return None


def get_cipher_txt_blob(okta_tenant_url, user_id, cipher_plain_text_key, profile_code):
    try:
        response = CipherTxtBlob.client.get_item(
            Key={
                Config.CUST_IDP_TENANT: {
                    "S": okta_tenant_url
                },
                Config.CIPHER_SORT_KEY: {
                    "S": user_id
                },
            },
            TableName=Config.CIPHER_TBL_NAME,
        )
        return response['Item'][cipher_plain_text_key]['S'], response['Item'][profile_code]['S']
    except Exception as e:
        return None, None


def get_item(okta_tenant_url, user_id):
    try:
        response = CipherTxtBlob.client.get_item(
            Key={
                Config.CUST_IDP_TENANT: {
                    "S": okta_tenant_url
                },
                Config.CIPHER_SORT_KEY: {
                    "S": user_id
                },
            },
            TableName=Config.CIPHER_TBL_NAME,
        )
        return response['Item']
    except Exception as e:
        return http_exception.error_handlers.Enroll_Marshmallow_JSON_Formation_Failed


def update_cipher_txt_blob(okta_tenant_url, user_id, cipher_plain_text_key, cipher_text_blob):
    try:
        response = CipherTxtBlob.client.update_item(
            TableName=Config.CIPHER_TBL_NAME,
            Key={
                Config.CUST_IDP_TENANT: {
                    "S": okta_tenant_url
                },
                Config.CIPHER_SORT_KEY: {
                    "S": user_id
                },
            },
            ExpressionAttributeNames={
                '#factor': cipher_plain_text_key,
            },
            ExpressionAttributeValues={
                ':factor_value': {
                    'S': cipher_text_blob,
                },
            },
            UpdateExpression='SET #factor = :factor_value'

        )
        return response
    except Exception as e:
        return None










# client = Client(host=Config.host,
#                 request_headers=request_headers)


# token_client = Client(host=introspect_api.ISSUER,
#                     request_headers=request_headers)


# def update_configuration_for_user(user_id, enrollment_info, card_uid, username):
#     print('Updating credentials in Okta for the user id: ', user_id, 'in app id:', Config.app_id)
#     client = Client(host=Config.host,
#                     request_headers=request_headers)
#     data = {
#         "profile": {
#             "userName": username,
#             "cardUID": card_uid,
#             "tectangoRFIDConfig": json.loads(enrollment_info)
#         }
#     }
#
#     # Api end point to update app profile attributes
#     # {{url}}/api/v1/apps/{{appId}}/users/{{userId}}
#     response = client.api.v1.apps._(Config.app_id).users._(user_id).post(request_body=data)
#     json_response_dict = response.to_dict
#     print("Response after creds saving: ", json_response_dict)
#     return response.body
#     # return json_response_dict


# def validate_card_uid_for_last_login(card_uid):
#     tectango_rfid_config_data = validate_card_uid(card_uid)
#     if tectango_rfid_config_data.__contains__("_embeddedData"):
#         tectango_rfid_config_in_dict = json.loads(tectango_rfid_config_data)
#
#         encrypted_password = tectango_rfid_config_in_dict['_embeddedData']['user']['profile']['secret']
#         print(encrypted_password)
#         cipher_text_blob_of_encrypted_password = tectango_rfid_config_in_dict['_embeddedData']['user']['cipherTextBlob']['secret']
#         decrypted_password = decrypt_attribute(encrypted_password, cipher_text_blob_of_encrypted_password)
#         final_data = tectango_rfid_config_data.replace(encrypted_password, decrypted_password)
#         print(final_data)
#         print(tectango_rfid_config_data)
#         return final_data, tectango_rfid_config_data
#     else:
#         return None, tectango_rfid_config_data


'''
# Enrollment JSON data without offline structure
# Enrollment JSON Template which needs to be saved under user app profile attribute

def hardcoded_enrollment_data(user_id, email, username, password, last_login_time_stamp, domainName, pin, cipher_text_blob_of_encrypted_password):
    enrollment_JSON_stored_in_okta =  {
        "_embeddedData": {
            "user": {
                "profile": {
                    "userID": user_id,
                    "email": email,
                    "upnName": "username@upnname.com",
                    "samAccountName": username,
                    "alias": "aliasname",
                    "secret": password,
                    #"cipherTextBlobOfPassword": cipher_text_blob_of_encrypted_password,
                    "pin": pin,
                    "environment": {
                        "userType": "domain",
                        "DomainName": domainName,
                        "environmentName": "tecnics-dev"
                    }
                },
                "lastLoginInfo": {
                    "lastLoginTimeStamp": last_login_time_stamp,
                    "enrollmentTimeStamp": "epoch time",
                    "userNameType": "UPN",
                    "mfa": "push"
                },
                "cipherTextBlob": {
                    "secret": cipher_text_blob_of_encrypted_password
                }
            },
        }
    }
    return enrollment_JSON_stored_in_okta

'''


#              },
#             "offline": {
#                 "factors": {
#                     "offlineTOTP": {
#                         "secretKey": "null"
#                     },
#                     "u2f": {
#                         "secretKey": "null"
#                     }
#                 }
#             },


# # Enrollment JSON data without offline structure.
# # Enrollment JSON Template which needs to be saved under user app profile attribute.
def hardcoded_enrollment_data(user_id, email, username, password, last_login_time_stamp, domain_name, pin,
                              cipher_text_blob_of_encrypted_password):
    enrollment_json_stored_in_okta = {
        "_embeddedData": {
            "user": {
                "profile": {
                    "userID": user_id,
                    "email": email,
                    "upnName": "username@upnname.com",
                    "samAccountName": username,
                    "alias": "aliasname",
                    "secret": password,
                    # "cipherTextBlobOfPassword": cipher_text_blob_of_encrypted_password,
                    "pin": pin,
                    "environment": {
                        "userType": "domain",
                        "DomainName": domain_name,
                        "environmentName": "tecnics-dev"
                    }
                },
                "lastLoginInfo": {
                    "lastLoginTimeStamp": last_login_time_stamp,
                    "enrollmentTimeStamp": "epoch time",
                    "userNameType": "UPN",
                    "mfa": "push"
                },
                "cipherTextBlob": {
                    # cipher_key: cipher_value
                    "secret": cipher_text_blob_of_encrypted_password,
                }
            },
        }
    }
    return enrollment_json_stored_in_okta

# Enrollment JSON Template which needs to be saved under user app profile attribute
# def enrollment_data(user_id, email, username, password, last_login_time_stamp, domainName, pin, cipher_text_blob_of_encrypted_password):
#     enrollment_JSON_stored_in_okta =  {
#         "_embeddedData": {
#             "user": {
#                 "profile": {
#                     "userID": user_id,
#                     "email": email,
#                     "upnName": "username@upnname.com",
#                     "samAccountName": username,
#                     "alias": "aliasname",
#                     "secret": password,
#                     #"cipherTextBlobOfPassword": cipher_text_blob_of_encrypted_password,
#                     "pin": pin,
#                     "environment": {
#                         "userType": "domain",
#                         "DomainName": domainName,
#                         "environmentName": "tecnics-dev"
#                     }
#                 },
#                 "lastLoginInfo": {
#                     "lastLoginTimeStamp": last_login_time_stamp,
#                     "enrollmentTimeStamp": "epoch time",
#                     "userNameType": "UPN",
#                     "mfa": "push"
#                 },
#                 "cipherTextBlob": {
#                     "secret": cipher_text_blob_of_encrypted_password
#                 }
#             },
#             "offline": {
#                 "factors": {
#                     "offlineTOTP": {
#                         "secretKey": "null"
#                     },
#                     "u2f": {
#                         "secretKey": "null"
#                     }
#                 }
#             },
#         }
#     }
#     return enrollment_JSON_stored_in_okta
