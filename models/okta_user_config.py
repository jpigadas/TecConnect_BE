#from EnrollmentMS.app.controllers.tectango_rfid_routes import *
#from AuthenticationMS.app.controllers.tectango_rfid_routes import *
import json


class UserProfile:
    def __init__(self, user):
        user = json.loads(user)
        tectangoRFIDConfig = user['profile']['tectangoRFIDConfig']
        tectangoRFIDConfig = json.loads(tectangoRFIDConfig)
        self.user_data = tectangoRFIDConfig['_embeddedData']
        self.user_id = tectangoRFIDConfig['_embeddedData']['user']['profile']['userID']
        # self.cipher_text_blob = tectangoRFIDConfig['_embeddedData']['user']['cipherTextBlob']
        self.tectango_rfid_config = tectangoRFIDConfig
        self.user_name = tectangoRFIDConfig['_embeddedData']['user']['profile']['samAccountName']
        self.profileKey = tectangoRFIDConfig['_embeddedData']['user']['profile']['profileKey']
        # self.cipher_text_blob_of_encrypted_password = tectangoRFIDConfig['_embeddedData']['user']['cipherTextBlob']['secret']
        self.previous_last_login_time_stamp = tectangoRFIDConfig['_embeddedData']['user']['lastLoginInfo']['lastLoginTimeStamp']
        self.user_profile = tectangoRFIDConfig['_embeddedData']['user']['profile']
        if json.dumps(tectangoRFIDConfig).__contains__("profileCode"):
            self.profileCode = tectangoRFIDConfig['_embeddedData']['user']['profile']['profileCode']
        else:
            self.profileCode = None
        if json.dumps(tectangoRFIDConfig).__contains__("offline"):
            self.offline_enrolled_factors = tectangoRFIDConfig['_embeddedData']['offline']['factors']
            if self.offline_enrolled_factors.__contains__("u2f"):
                self.encrypted_offline_u2f_secret_key = tectangoRFIDConfig['_embeddedData']['offline']['factors']['u2f']['offlineProfileKey']
                # self.cipher_text_blob_of_offline_u2f = tectangoRFIDConfig['_embeddedData']['user']['cipherTextBlob']['u2f']
            if self.offline_enrolled_factors.__contains__("offlineTOTP"):
                self.encrypted_offline_totp_secret_key = tectangoRFIDConfig['_embeddedData']['offline']['factors']['offlineTOTP']['offlineProfileKey']
                # self.cipher_text_blob_of_offline_totp = tectangoRFIDConfig['_embeddedData']['user']['cipherTextBlob']['offlineTOTP']


class UserProfileEnroll:
    def __init__(self, user):
        user = json.loads(user)
        self.user_id = user['_embeddedData']['user']['profile']['userID']
        self.user_name = user['_embeddedData']['user']['profile']['samAccountName']


class Payload:
    def __init__(self, payload):
        self.payload_data = json.dumps(payload)
        if payload.__contains__('username'): self.username = payload['username']
        if payload.__contains__('password'): self.password = payload['password']
        if payload.__contains__('cardUID'): self.cardUID = payload['cardUID']
        if payload.__contains__('domainName'): self.domainName = payload['domainName']
        if payload.__contains__('oktaTenantUrl'): self.oktaTenantUrl = payload['oktaTenantUrl']
        if payload.__contains__('pin'):
            self.pin = payload['pin']
        else:
            self.pin = None
        if payload.__contains__('lastLoginTimeStamp'): self.lastLoginTimeStamp = payload['lastLoginTimeStamp']
        if payload.__contains__('factorType'): self.factorType = payload['factorType']
        if payload.__contains__('secretKey'): self.secretKey = payload['secretKey']
        if payload.__contains__('last_login_time'): self.last_login_time = payload['last_login_time']


class CipherPlainText:
    cipher_text_blob_of_encrypted_password: str
    cipher_text_blob_of_pin: str

    def __init__(self, cipher_text_blob_of_encrypted_password, cipher_text_blob_of_pin):
        CipherPlainText.cipher_text_blob_of_encrypted_password = cipher_text_blob_of_encrypted_password
        if cipher_text_blob_of_pin is None:
            CipherPlainText.cipher_text_blob_of_pin = ""
        else:
            CipherPlainText.cipher_text_blob_of_pin = cipher_text_blob_of_pin


class FactorProfile:
    security_key_name: str

    def __init__(self, security_key_name: str) -> None:
        self.security_key_name = security_key_name


class Fido2:
    secret: str
    factor_profile: FactorProfile

    def __init__(self, secret: str, factor_profile: FactorProfile) -> None:
        self.secret = secret
        self.factor_profile = factor_profile


class PurplePin:
    value: int

    def __init__(self, value: int) -> None:
        self.value = value


class OfflineFactors:
    fido2: Fido2
    pin: PurplePin

    def __init__(self, fido2: Fido2, pin: PurplePin) -> None:
        self.fido2 = fido2
        self.pin = pin


class Offline:
    factors: OfflineFactors

    def __init__(self, factors: OfflineFactors) -> None:
        self.factors = factors


class FluffyPin:
    key_length: int
    includes_characters: bool

    def __init__(self, key_length: int, includes_characters: bool) -> None:
        self.key_length = key_length
        self.includes_characters = includes_characters


class SecurityQuestions:
    pass

    def __init__(self, ) -> None:
        pass


class PoliciesFactors:
    pin: FluffyPin
    security_questions: SecurityQuestions

    def __init__(self, pin: FluffyPin, security_questions: SecurityQuestions) -> None:
        self.pin = pin
        self.security_questions = security_questions


class Policies:
    factors: PoliciesFactors

    def __init__(self, factors: PoliciesFactors) -> None:
        self.factors = factors


class LastLoginInfo:
    last_login_time_stamp: str
    enrollment_time_stamp: str
    user_name_type: str
    mfa: str

    def __init__(self, last_login_time_stamp: str, enrollment_time_stamp: str, user_name_type: str, mfa: str) -> None:
        self.last_login_time_stamp = last_login_time_stamp
        self.enrollment_time_stamp = enrollment_time_stamp
        self.user_name_type = user_name_type
        self.mfa = mfa


class Profile:
    email: str
    upn_name: str
    sam_account_name: str
    alias: str

    def __init__(self, email: str, upn_name: str, sam_account_name: str, alias: str) -> None:
        self.email = email
        self.upn_name = upn_name
        self.sam_account_name = sam_account_name
        self.alias = alias


class User:
    profile: Profile
    last_login_info: LastLoginInfo

    def __init__(self, profile: Profile, last_login_info: LastLoginInfo) -> None:
        self.profile = profile
        self.last_login_info = last_login_info


class EmbeddedData:
    user: User
    offline: Offline
    policies: Policies

    def __init__(self, user: User, offline: Offline, policies: Policies) -> None:
        self.user = user
        self.offline = offline
        self.policies = policies


class Welcome10:
    embedded_data: EmbeddedData

    def __init__(self, embedded_data: EmbeddedData) -> None:
        self.embedded_data = embedded_data
