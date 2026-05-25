import jwt

from django.conf import settings


def verify_grant_token(token: str):
    payload = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[getattr(settings, "JWT_ALG", "HS256")],
    )
    return payload
