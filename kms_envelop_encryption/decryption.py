import boto3
import base64

#import http_exception.error_handlers
from config import Config
from cryptography.fernet import Fernet


def decrypt_attribute(encrypted_plain_text, cipher_text_blob, aws_kms_arn):
    try:
        # # Get a KMS client
        client = boto3.client(Config.KMS, Config.REGION)
        decrypted_key = client.decrypt(CiphertextBlob=base64.b64decode(cipher_text_blob.encode()), KeyId=aws_kms_arn)
        # # Encode decrypted key to base64 by including Plaintext of decrypted_key.
        f = Fernet(base64.b64encode(decrypted_key["Plaintext"]))
        # # Use the encrypted_plain_text key to decrypt the secret message data.
        decrypted_plain_text = f.decrypt(encrypted_plain_text.encode())
        print("INFO :: decrypted successfully")
        return decrypted_plain_text.decode()
    except Exception as e:
        return None
