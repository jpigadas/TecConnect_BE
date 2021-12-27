from marshmallow import post_load, Schema, fields


# jsonResponseSchema class
class JsonResponseSchema(Schema):
    user_id = fields.Str()
    email = fields.Email()

    # @post_load
    # def make_user(self, data, **kwargs):
    #     return JsonResponse(**data)


'''

# Deserialization classes
class JsonResponse:
    def __init__(self, user_id, email, last_login_time_stamp):
        self.user_id = user_id
        self.email = email


class Payloads:
    def __init__(self, username, password, cardUID, pin, domainName, lastLoginTimeStamp):
        self.username = username
        self.password = password
        self.cardUID = cardUID
        self.pin = pin
        self.domainName = domainName
        self.lastLoginTimeStamp = lastLoginTimeStamp


# PayloadSchema class
class PayloadSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    cardUID = fields.Int()
    pin = fields.Int()
    domainName = fields.Str()
    lastLoginTimeStamp = fields.DateTime()

    # @post_load
    # def make_user(self, data, **kwargs):
    #     return Payloads(**data)

'''
