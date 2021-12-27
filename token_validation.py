from flask import request
from init import app
import http_exception.error_handlers
from okta_jwt_verifier import JWTVerifier


# async def jwt_verifier(issuer, client_id, access_token):
#     try:
#         jwt_verifier = JWTVerifier(issuer, client_id, 'api://default')
#         await jwt_verifier.verify_access_token(access_token)
#         print('Token validated successfully.')
#         # return "Token validated successfully."
#         return http_exception.error_handlers.TOKEN_VALIDATED_SUCCESSFULLY
#     except Exception as e:
#         print("Error:", e)
#         return http_exception.error_handlers.SIGNATURE_HAS_EXPIRED


@app.route('/api/v1/tectango/introspect', methods=['POST'])
async def introspect_api():
    try:
        payload = request.json
        access_token = payload.get('accessToken')
        issuer = payload.get('issuer')
        client_id = payload.get('clientId')
        # access_token = payload.args.get("access_token")
        # issuer = "https://tecnics-stage.oktapreview.com/oauth2/default"
        # client_id = "0oa128gzo8nQxZFGY0h8"
        # access_token_1 = "eyJraWQiOiJrNkh6WVFXYi1NaG1OX21DSWF6dmJGZXlreUxfSnJKYTdpV2d2RTJUYXcwIiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULmdHYUVsbjdGWVF6LXViWjBfeV9sVmcwSUJRbVFleUxRQzFSbDFJNHhHZzAiLCJpc3MiOiJodHRwczovL3RlY25pY3Mtc3RhZ2Uub2t0YXByZXZpZXcuY29tL29hdXRoMi9kZWZhdWx0IiwiYXVkIjoiYXBpOi8vZGVmYXVsdCIsImlhdCI6MTYzNjQ1MjUyMSwiZXhwIjoxNjM2NDU2MTIxLCJjaWQiOiIwb2ExMmJnbGgwZE1Pek1yOTBoOCIsInVpZCI6IjAwdTEyYTF5cnYwcDFhaUpGMGg4Iiwic2NwIjpbIm9wZW5pZCIsImVtYWlsIl0sInN1YiI6InNhbWFudGhhLnNtaXRoQGNyZWRlbnRpLmlvIn0.Y7XAU7lS1FXYgCj9LA_AB2rbxiT5LFbi5imlz6McamG9ebJZq66Bq9h5sF9taK_q1Yzos_nkkcrrrdp5yTBk0ENFwJazXnaJjyMqEXRzI3MuRDiwmjIBrFhLBKlmGrdwaY3UBymx4Ye0VhjB7Vb08E3cz4K93hgwdzMZAWxbpHcCPM_wBQHSTJtwvBN3Zlu9jnwTnidvAvCROgGUSUruV4IEZ29ysXPX7bYAg5uEKL9ihrb9oz0lk7b2tMjQNDD8yOvrgMqtw9c4FAb9TOgQTI8C0gkNao4YS2pAvYyoguVcRrrYR6JRcMtk812jcs6d7R-3EVWJpkls7cPRl1DzKQ"
        # access_token = "eyJraWQiOiJrNkh6WVFXYi1NaG1OX21DSWF6dmJGZXlreUxfSnJKYTdpV2d2RTJUYXcwIiwiYWxnIjoiUlMyNTYifQ.eyJ2ZXIiOjEsImp0aSI6IkFULkpldDJQbENYUjdnLXlYTjNVVXcydWdTMHBQdGU3UnNhZFFXWUczRk5YOHMiLCJpc3MiOiJodHRwczovL3RlY25pY3Mtc3RhZ2Uub2t0YXByZXZpZXcuY29tL29hdXRoMi9kZWZhdWx0IiwiYXVkIjoiYXBpOi8vZGVmYXVsdCIsImlhdCI6MTYzNjQ1NzE2OCwiZXhwIjoxNjM2NDYwNzY4LCJjaWQiOiIwb2ExMmJnbGgwZE1Pek1yOTBoOCIsInVpZCI6IjAwdTEyYTF5cnYwcDFhaUpGMGg4Iiwic2NwIjpbImVtYWlsIiwib3BlbmlkIl0sInN1YiI6InNhbWFudGhhLnNtaXRoQGNyZWRlbnRpLmlvIn0.JlfGjfS7-wqocBeNG4NHlW3L1vBsmZUW8G7LnxEBZqH_X4OpjUl9RtVSyn7yudHaRpqinivgeG4rUJVhQBGoVWznG0P1A4n-5BvDNhbiI0VTYFM7RAWITlU_Svd0MpU6jM5wesBdPBHwI_bDD72WPXHSYNFd1hC8cLOxkizE9Kr4YdsjNyRZ3khWLsEH60EZIKcuO0wRZabss_UwAdDKPszCYWi5XR2ieaxm88kVkjoNCXKvQortFfByMCSOKb-jCR6hjZfN_y4LKHiKKeL7KFJJ0X8LGjv4JckY1n-bVwZEOL9Rh6aHAqOw-hXDeb0IHJoxKjBz-b4-tCU1xHKSEA"

        # response = await jwt_verifier(issuer, client_id, access_token)
        # return response
        jwt_verifier = JWTVerifier(issuer, client_id, 'api://default')
        await jwt_verifier.verify_access_token(access_token)
        print('Token validated successfully.')
        # return "Token validated successfully."
        return http_exception.error_handlers.TOKEN_VALIDATED_SUCCESSFULLY
    except Exception as e:
        print("Error:", e)
        print("except")
        return http_exception.error_handlers.SIGNATURE_HAS_EXPIRED
