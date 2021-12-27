import os
import boto3
#from botocore.exceptions import ClientError


class Config(object):
    REGION = os.environ['AWS_KMS_REGION']
    DYNAMODB_TABLE_NAME = os.environ['DYNAMODB_TABLE_NAME']
    #dynamodb_tbl_name = "tbl_dev_credenti_config_v2"
    OFFLINE_PROFILE_KEY = "offlineProfileKey"
    PROFILE_KEY = "profileKey"
    PROFILE_CODE = "profileCode"
    CUST_IDP_TENANT = "pk_cust_idp_url"
    PRODUCT_SORT_KEY = "sk_product_sku"
    CIPHER_SORT_KEY = "sk_user_id"
    CARD_UID = "cardUID"
    CIPHER_TBL_NAME = "tbl_dev_tectango_cipher_text_profile"
    U2F = "u2f"
    OFFLINE_TOTP = "offlineTOTP"
    OFFLINE = "offline"
    LAST_LOGIN_TIME = "last_login_time"
    FACTOR_TYPE = "factorType"
    DYNAMODB = "dynamodb"
    PRODUCT_TECTANGO = "tectango"
    USER_NAME = "username"
    EMBEDDED_DATA = "_embeddedData"
    PASSWORD = "password"
    PIN = "pin"
    KMS = "kms"

class CipherTxtBlob:
    client = boto3.client('dynamodb', region_name=os.environ['AWS_KMS_REGION'])


class DevelopmentConfig(Config):
    TEMPLATES_AUTO_RELOAD = True
    DEBUG = True


class TestingConfig(Config):
    TESTING = True


class ProductionConfig(Config):
    DEBUG = False


app_config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig
}















# dynamodb_tbl_name = "tbl_dev_credenti_config_v1"
# region = "us-east-1"
# offline_profile_key = os.environ['OFFLINE_PROFILE_KEY']
# profile_key = os.environ['PROFILE_KEY']

# region = "us-east-1"
    # host = "https://tecnics-dev.oktapreview.com"
    # app_id = "0oa1088m2uxGYD8J80h8"
    # dynamodb_tbl_name = "client_config_data"
# region = "us-east-1"
#     dynamodb_tbl_name = "client_config_data"

# region = 'us-east-1'
# host = 'https://tecnics-dev.oktapreview.com'
# app_id = '0oa1088m2uxGYD8J80h8'
# dynamodb_tbl_name = "client_config_data"