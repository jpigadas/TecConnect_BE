"""
    Uses only Serialization concept and returns JSON Data
"""
from marshmallow import Schema, fields


class LastLoginInfo:
    def __init__(self, last_login_time_stamp, epoch_time, user_name_type, mfa):
        self.lastLoginTimeStamp = last_login_time_stamp
        self.enrollmentTimeStamp = epoch_time
        self.userNameType = user_name_type
        self.mfa = mfa


class Environment:
    def __init__(self, domain, domainName, envName):
        self.userType = domain
        self.DomainName = domainName
        self.environmentName = envName


class Profile:
    def __init__(self, user_id, email, upnname, username, alias, password, pin, env_data):
        self.user_id = user_id
        self.email = email
        self.upnName = upnname
        self.samAccountName = username
        self.alias = alias
        self.secret = password
        self.pin = pin
        self.environment = env_data


class User:
    def __init__(self, profile_data, last_login_info_data):
        self.profile = profile_data
        self.lastLoginInfo = last_login_info_data


class Embedded:
    def __init__(self, user_data):
        self.user = user_data


class JsonData:
    def __init__(self, embedded_data):
        self._embeddedData = embedded_data


# userSchema class
class UserSchema(Schema):
    user_id = fields.String()
    samAccountName = fields.String()
    secret = fields.String()
    pin = fields.Integer()
    upnName = fields.String()
    email = fields.Email()
    alias = fields.String()
    userType = fields.String()
    DomainName = fields.String()
    environmentName = fields.String()
    environment = fields.Dict()
    lastLoginTimeStamp = fields.String()
    enrollmentTimeStamp = fields.String()
    userNameType = fields.String()
    mfa = fields.String()


# dataSchema class
class DataSchema(Schema):
    lastLoginInfo = fields.Dict()
    profile = fields.Dict()
    user = fields.Dict()
    _embeddedData = fields.Dict()


user_schema = UserSchema()
data_schema = DataSchema()


# Function for creating json data (serialization)
def enrollment_data(payload, json_response_dict):
    username = payload.get('username')
    password = payload.get('password')
    domainName = payload.get('domainName')
    pin = payload.get('pin')
    last_login_time_stamp = json_response_dict['lastLogin']
    email = json_response_dict['profile']['email']
    user_id = json_response_dict['id']

    # creating object for Environment Class using env data and passing it for serialization
    env = Environment("domain", domainName, "tecnics-dev")
    env_data = user_schema.dump(env)

    # creating object for Profile Class using env and user data and passing it for serialization
    user_profile = Profile(user_id, email, "username@upnname.com", username, "aliasName", password, pin, env_data)
    profile_data = user_schema.dump(user_profile)

    # creating object for LastLoginInfo Class using lastlogin data and passing it for serialization
    lastlogininfo = LastLoginInfo(last_login_time_stamp, "epoch time", "UPN", "push")
    last_login_info_data = user_schema.dump(lastlogininfo)

    # creating object for User Class using profile_data & lastLoginInfo data and passing it for serialization
    user = User(profile_data, last_login_info_data)
    user_data = data_schema.dump(user)

    embedded = Embedded(user_data)
    embedded_data = data_schema.dump(embedded)

    json_obj = JsonData(embedded_data)
    json_data = data_schema.dump(json_obj)

    return json_data
