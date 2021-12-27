import boto3
import base64
#import http_exception.error_handlers
from config import Config
from cryptography.fernet import Fernet



def encrypt_data(plain_text, aws_kms_arn):
    try:
        # # Get a KMS client.
        print("Info :: Encrypting data")
        client = boto3.client(Config.KMS, Config.REGION)
        # # secret message to encrypt.
        plaintext = plain_text
        # # Generate a new data key.
        response = client.generate_data_key(
            # # The identifier of the CMK to use to encrypt the data key. You can use the key ID or Amazon Resource Name (
            # # ARN) of the CMK, or the name or ARN of an alias that refers to the CMK.
            KeyId=aws_kms_arn,
            # # Specifies the type of data key to return.
            KeySpec="AES_256"
        )
        # # The response return the plaintext and encrypted(cipher_text_blob) version of the data key.
        plain_data_key = base64.b64encode(response["Plaintext"])
        # # ciphet text blob should be stored under database for decryption.
        cipher_text_blob = base64.b64encode(response["CiphertextBlob"])
        # # Use the plaintext key to encrypt our data, and then throw it away.
        f = Fernet(plain_data_key)
        encrypted_plain_text = f.encrypt(bytes(plaintext, encoding='utf8'))
        # # save encrypted_plain_text and cipher_text_blob, which helps to decrypt the plaintext from encrypted data.
        return encrypted_plain_text.decode(), cipher_text_blob.decode()
    except Exception as e:
        return None, None


