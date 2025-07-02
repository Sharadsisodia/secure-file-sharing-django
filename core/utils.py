import jwt
from django.conf import settings
from datetime import datetime, timedelta

def generate_token(data, expiry_minutes=15):
    payload = data.copy()
    payload['exp'] = datetime.utcnow() + timedelta(minutes=expiry_minutes)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

def decode_token(token):
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
