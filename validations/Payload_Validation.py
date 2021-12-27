from marshmallow import Schema, fields, ValidationError


# validating cardUID
from models.okta_user_config import Payload


def carduid_validation(uid):
    if uid < 0:
        uid = str(uid)[1:]
    uid_len = len(str(uid))
    if uid_len == 0:
        raise ValidationError("Invalid cardUID")


# validating pin (Min length 4 digits)
def pin_validation(pin):
    pin = pin.lower()
    if not (pin == "null"):
        try:
            pin_len = len(pin)
            pin = int(pin)
            if pin_len < 4:
                raise ValidationError("Pin was not meeting the requirements")
        except Exception as err:
            print(err)
            raise ValidationError("Entered Pin is not a valid number")


# SchemaClass for validating primary enroll payload data
class PrimaryEnrollValidationSchema(Schema):
    username = fields.String(required=True)
    password = fields.String(required=True)
    # Validating cardUID
    cardUID = fields.Integer(required=True, validate=carduid_validation)
    domainName = fields.String(required=True)
    # supports pin of minimum 4 digits
    pin = fields.String(validate=pin_validation)
    # check for last login time stamp
    lastLoginTimeStamp = fields.Integer(required=True)
    oktaTenantUrl = fields.String(required=True)


# SchemaClass for validating primary enroll payload data
class OfflineEnrollValidationSchema(Schema):
    # Validating cardUID
    cardUID = fields.Integer(required=True, validate=carduid_validation)
    factorType = fields.String(required=True)
    secretKey = fields.String(required=True)
    oktaTenantUrl = fields.String(required=True)


# AuthnPayloadSchema class for validating data
class AuthnPayloadSchema(Schema):
    # Validating cardUID
    cardUID = fields.Integer(required=True, validate=carduid_validation)
    last_login_time = fields.Integer()
    pin = fields.String(validate=pin_validation)
    password = fields.String()
    oktaTenantUrl = fields.String(required=True)


# function for primary enroll payload data validation (deserialization)
def primary_enroll_data_validation(payload):
    try:
        # Creating schema class object
        primary_enroll_schema = PrimaryEnrollValidationSchema()
        # Passing payload for validation
        payload_result = primary_enroll_schema.validate(payload)
        # Verifying the validation result
        if len(payload_result) != 0:
            print("payload_result: ", payload_result)
            return None
        get_payload = Payload(payload)
        return get_payload
    except ValidationError as err:
        print(err.messages)
        return None


# function for offline enroll payload data validation (deserialization)
def offline_enroll_data_validation(payload):
    try:
        # Creating schema class object
        offline_enroll_schema = OfflineEnrollValidationSchema()
        # Passing payload for validation
        payload_result = offline_enroll_schema.validate(payload)
        # Verifying the validation result
        if len(payload_result) != 0:
            print("payload_result: ", payload_result)
            return None
        get_payload = Payload(payload)
        return get_payload
    except ValidationError as err:
        print(err.messages)
        return None


# AuthnMS Payload Validation Function
def authn_payload_data_validation(payload):
    try:
        # Creating schema class object
        payload_schema = AuthnPayloadSchema()
        # Passing payload for validation
        payload_result = payload_schema.validate(payload)
        # Verifying the validation result
        if len(payload_result) != 0:
            print("Info :: verifying payload result - ", payload_result)
            return None
        get_payload = Payload(payload)
        return get_payload
    except ValidationError as err:
        print(err.messages)
        return False
