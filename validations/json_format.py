import json

from marshmallow import ValidationError

# from app.kms_envelop_encryption import encrypt_data
# from app.validations.deserialization import JsonResponseSchema
# from app.validations.serialization import UserSchema, DataSchema, Environment, Profile, LastLoginInfo, User, Embedded, \
#     JsonData, CipherTextBlob


# creating objects for SerializationSchemas
import http_exception.error_handlers
from models.okta_user_config import UserProfileEnroll, CipherPlainText
from validations.deserialization import JsonResponseSchema
from validations.serialization import UserSchema, DataSchema, Environment, Profile, LastLoginInfo, \
    CipherTextBlob, User, Embedded, JsonData
from kms_envelop_encryption.encryption import encrypt_data

user_schema = UserSchema()
data_schema = DataSchema()

# creating objects for DeserializationSchemas
# payload_schema = PayloadSchema()
json_resp_schema = JsonResponseSchema()


# Function for creating json data (deserialization)
def enrollment_data(payloads, response, aws_kms_arn):
    try:
        # payload data
        username = payloads.username
        password = payloads.password

        json_response_dict = response.to_dict

        # # Encrypting Password using Envelop encryption.
        # Generating Encrypted Password and cipher_text_blob_of_encrypted_password which help in decryption.
        encrypted_password, cipher_text_blob_of_encrypted_password = encrypt_data(password, aws_kms_arn)
        if encrypted_password is None:
            return False, None
        domain_name = payloads.domainName
        pin = payloads.pin
        encrypted_pin = None
        if pin is not None:
            encrypted_pin, cipher_text_blob_of_pin = encrypt_data(pin, aws_kms_arn)
            if encrypted_pin is None:
                return False, None
            CipherPlainText(cipher_text_blob_of_encrypted_password, cipher_text_blob_of_pin)
        else:
            CipherPlainText(cipher_text_blob_of_encrypted_password, None)
        last_login_time_stamp = payloads.lastLoginTimeStamp

        # json_response_dict data
        email = json_response_dict['profile']['email']
        user_id = json_response_dict['id']
        json_response = {"user_id": user_id, "email": email}


        # validating the data using validation function (returns dict of validation errors)

        # payload validation was done by data_validation() in previous step
        # payload_result = payload_schema.validate(payload)

        json_response_result = json_resp_schema.validate(json_response)

        # check for raised errors from validation function
        if len(json_response_result) != 0:
            raise ValidationError("Invalid Data")

        # Serialization for JSON Format
        # creating object for Environment Class using env data and passing it for serialization
        env = Environment("domain", domain_name, "tecnics-dev")
        env_data = user_schema.dump(env)

        # creating object for Profile Class using env and user data and passing it for serialization
        user_profile = Profile(user_id, email, "username@upnname.com", username, "aliasName", encrypted_password, encrypted_pin, env_data)
        profile_data = user_schema.dump(user_profile)

        # creating object for LastLoginInfo Class using lastlogin data and passing it for serialization
        lastlogininfo = LastLoginInfo(last_login_time_stamp, "epoch time", "UPN", "push")
        last_login_info_data = user_schema.dump(lastlogininfo)


        # creating object for CipherTextBlob Class using cipher_text_blob_of_encrypted_password and passing it for serialization
        # cipher_text_blob = CipherTextBlob(cipher_text_blob_of_encrypted_password)
        # cipher_text_blob_of_encrypted_password_data = user_schema.dump(cipher_text_blob)


        # creating object for User Class using profile_data & lastLoginInfo_data &
        # cipher_text_blob_of_encrypted_password_data and passing it for serialization
        #user = User(profile_data, last_login_info_data, cipher_text_blob_of_encrypted_password_data)
        user = User(profile_data, last_login_info_data)
        user_data = data_schema.dump(user)

        # creating object for Embedded Class using user_data and passing it for serialization
        embedded = Embedded(user_data)
        embedded_data = data_schema.dump(embedded)

        # creating object for JsonData Class using embedded_data and passing it for serialization
        json_obj = JsonData(embedded_data)
        json_data = data_schema.dump(json_obj)
        #print(json.dumps(json_data))
        user = UserProfileEnroll(json.dumps(json_data))
        return json_data, user

    except Exception as e:
        return None, None
        # print(e.messages)
        # return False, None
        # print(e.valid_data)


'''
        # code with creating object while deserialization
        # performing deserialization on payload and json_response
        result1 = payload_schema.load(payload)
        result2 = json_resp_schema.load(json_response)

        # Serialization
        username = result1.username
        password = encrypt_attribute(result1.password)
        domainName = result1.domainName
        pin = result1.pin
        last_login_time_stamp = result2.last_login_time_stamp
        email = result2.email
        user_id = result2.user_id

'''
