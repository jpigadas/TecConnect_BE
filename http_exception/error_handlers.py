import json
from werkzeug.exceptions import HTTPException
from init import app


@app.errorhandler(HTTPException)
def handle_exception(e):
    print("Info :: In error handler")
    response = e.get_response()
    response.data = json.dumps({
        "errorCode": e.code,
        "errorCauses": e.name,
        "errorSummary": e.description,
    })
    response.content_type = "application/json"
    return response


def template(code, name, description):
    # return {'message': {'errors': {'body': data}}, 'status_code': code}
    response = {
        "errorCode": code,
        "errorCauses": name,
        "errorSummary": description,
    }
    return response


# # Exceptions # #
#####
USER_SUCCESSFULLY_ENROLLED = template('E1000', 'Success', 'Enrollment API - User successfully enrolled - 200 success')
ENROLL_NOT_FOUND_EXCEPTION = template('E1001', 'User Not Found', 'Enrollment API - User is not authorized to perform this operation - 404 Not Found')
ENROLL_DYNAMODB_EXCEPTION = template('E1002', 'DynamoDB requested resource not found', 'Enrollment API - Internal error occurred while communicating with DynamoDB - 400 Bad Request')
ENROLL_REQUEST_NOT_VALID = template('E1003', 'Invalid JSON payload received', 'Enrollment API - The request was not valid or well formed - 400 Bad Request')
Enroll_Marshmallow_JSON_Formation_Failed = template('E1004', 'Marshmallow Validation Failed', 'Enrollment API - Marshmallow json formation failed - 400 Bad Request')
ENROLL_ENCRYPTION_FAILED = template('E1005', 'Envelop Encryption Failed', 'Enrollment API - The action or operation requested is invalid - 400 Bad Request')#, 'Please check your card and tap again')
ENROLL_CARD_UID_NOT_FOUND = template('E1006', 'Card UID not found', 'Enrollment API - Invalid Card UID. Please enter a valid card uid - 400 Bad Request')#, 'Please check your card and tap again')
ENROLL_UNSUPPORTED_FACTOR_TYPE = template('E1007', 'Invalid offline factor type', 'Enrollment API - The requested offline factor type is unsupported - 400 Bad Request')#Unsupported offline factor type.
ENROLL_UPDATE_CREDENTIALS_FAILED = template('E1008', 'Invalid client app id or User id', 'Enrollment API - Failed to Update of credentials to OKTA - 403 Forbidden')
ENROLL_DYNAMODB_FAILED = template('E1009', 'Failed to store or update the cipher text in DynamoDB', 'Enrollment API - Internal error occurred while communicating with DynamoDB - 400 Bad Request')
ENROLLMENT_FAILED = template('E1010', 'Enrollment failed', 'Enrollment API - Missing JSON payload data - 400 Bad Request')
######

######
AUTHN_REQUEST_NOT_VALID = template('E1010', 'Invalid JSON payload received', 'Authentication API - The request was not valid or well formed - 400 Bad Request')
AUTHN_DYNAMODB_EXCEPTION = template('E1011', 'DynamoDB requested resource not found', 'Authentication API - Internal error occurred while communicating with DynamoDB - 400 Bad Request')
AUTHN_CARD_UID_NOT_FOUND = template('E1012', 'Card UID not found', 'Authentication API - Invalid Card UID. Please enter a valid card uid - 400 Bad Request')#, 'Please check your card and tap again')
AUTHN_GET_CIPHER_TEXT_BLOB_FAILED = template('E1013', 'Failed to get cipher text blob from DynamoDB', 'Authentication API - Internal error occurred while communicating with DynamoDB - 400 Bad Request')
AUTHN_DECRYPTION_FAILED = template('E1014', 'Envelop Decryption Failed', 'Authentication API - The action or operation requested is invalid - 400 Bad Request')#, 'Please check your card and tap again')
AUTHN_ENCRYPTION_FAILED = template('E1015', 'Envelop Encryption Failed while updating profile', 'Authentication API - The action or operation requested is invalid - 400 Bad Request')#, 'Please check your card and tap again')
AUTHN_UPDATE_CREDENTIALS_FAILED = template('E1016', 'Invalid client app id or User id', 'Authentication API - Failed to Update of credentials to OKTA - 403 Forbidden')
AUTHN_DYNAMODB_FAILED = template('E1017', 'Failed to store or update the cipher text in DynamoDB', 'Authentication API - Internal error occurred while communicating with DynamoDB - 400 Bad Request')
AUTHENTICATION_FAILED = template('E1018', 'Authentication failed', 'Authentication API - Missing JSON payload data - 400 Bad Request')
######


#####
AUTHENTICATION_REQUEST_FAILED = template('E1002', 'Authentication request failed', 'The request was not valid.')
#ENROLL_REQUEST_NOT_VALID = template('E1003', 'Invalid data passed in payloads', 'Enrollment API - The request was not valid - 400 Bad Request')
#AUTHENTICATION_FAILED = template('E1004', 'Authentication failed', 'Something went wrong while authentication.')
PUBLIC_KEY_FORBIDDEN = template(403, "Forbidden",
                                "You don't have the permission to access the requested resource. It is either read-protected or not readable by the server.")
SOMETHING_WENT_WRONG = template("1808", "Failed", "Something went wrong.")
SIGNATURE_HAS_EXPIRED = template(400, "Signature has expired.", "JWT is invalid, expired, or revoked.")
TOKEN_VALIDATED_SUCCESSFULLY = template(200, "Token validated successfully", "JWT has been successfully verified")
#####


















# The requested Payloads was incorrect. '
# 'If you entered the Payloads manually '
# 'please check your spelling and try '
# 'again.



# @app.errorhandler(404)
# def not_found(e):
#     return "{Error: 404 Not Found}"