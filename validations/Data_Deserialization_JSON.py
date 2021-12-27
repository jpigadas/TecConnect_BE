"""
    Uses only Deserialization concept and returns JSON Data
"""
from marshmallow import post_load, Schema, fields, ValidationError


# class payloads
class Payloads:
    def __init__(self, username, password, card_uid, pin, domain_name):
        self.username = username
        self.password = password
        self.cardUID = card_uid
        self.pin = pin
        self.domainName = domain_name


# class JsonResponse
class JsonResponse:
    def __init__(self, user_id, email, last_login_time_stamp):
        self.user_id = user_id
        self.email = email
        self.last_login_time_stamp = last_login_time_stamp


# PayloadSchema class
class PayloadSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    cardUID = fields.Int()
    pin = fields.Int()
    domainName = fields.Str()

    @post_load
    def make_user(self, data, **kwargs):
        return Payloads(**data)


# jsonResponseSchema class
class JsonResponseSchema(Schema):
    user_id = fields.Str()
    email = fields.Email()
    last_login_time_stamp = fields.DateTime()

    @post_load
    def make_user(self, data, **kwargs):
        return JsonResponse(**data)


# creating objects for Schemas
schema1 = PayloadSchema()
schema2 = JsonResponseSchema()


# Function for creating json data (deserialization)
def enrollment_data(payload, json_response_dict):
    last_login_time_stamp = json_response_dict['lastLogin']
    email = json_response_dict['profile']['email']
    user_id = json_response_dict['id']
    json_response = {"user_id": user_id, "email": email, "last_login_time_stamp": last_login_time_stamp}

    try:
        # performing deserialization on payload and response data
        result1 = schema1.load(payload)
        result2 = schema2.load(json_response)
        # Json format to be return
        enrollment_JSON_stored_in_okta = {
            "_embeddedData": {
                "user": {
                    "profile": {
                        "user_id": result2.user_id,
                        "email": result2.email,
                        "upnName": "username@upnname.com",
                        "samAccountName": result1.username,
                        "alias": "aliasname",
                        "secret": result1.password,
                        "pin": result1.pin,
                        "environment": {
                            "userType": "domain",
                            "DomainName": result1.domainName,
                            "environmentName": "tecnics-dev"
                        }
                    },
                    "lastLoginInfo": {
                        # isoformat is to serialize datetime to json
                        "lastLoginTimeStamp": result2.last_login_time_stamp.isoformat(),
                        "enrollmentTimeStamp": "epoch time",
                        "userNameType": "UPN",
                        "mfa": "push"
                    }
                },
            }
        }

        return enrollment_JSON_stored_in_okta

    except ValidationError as e:
        print(e.messages)
        # print(e.valid_data)
