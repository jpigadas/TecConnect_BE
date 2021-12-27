from marshmallow import Schema, fields


# Serialization classes
class LastLoginInfo:
    def __init__(self, last_login_time_stamp, epoch_time, user_name_type, mfa):
        self.lastLoginTimeStamp = last_login_time_stamp
        self.enrollmentTimeStamp = epoch_time
        self.userNameType = user_name_type
        self.mfa = mfa


class CipherTextBlob:
    def __init__(self, cipher_text_blob_of_encrypted_password):
        self.profileKey = cipher_text_blob_of_encrypted_password


class Environment:
    def __init__(self, domain, domain_name, env_name):
        self.userType = domain
        self.DomainName = domain_name
        self.environmentName = env_name


class Profile:
    def __init__(self, user_id, email, upnname, username, alias, password, pin, env_data):
        self.userID = user_id
        self.email = email
        self.upnName = upnname
        self.samAccountName = username
        self.alias = alias
        self.profileKey = password
        if pin is not None:
            self.profileCode = pin
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
    userID = fields.String()
    samAccountName = fields.String()
    profileKey = fields.String()
    profileCode = fields.String()
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
    cipherTextBlob = fields.Dict()
