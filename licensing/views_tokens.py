import jwt

from rest_framework.decorators import api_view
from rest_framework.response import Response

from .token_verify import verify_grant_token


@api_view(["POST"])
def verify_token(request):
    token = (request.data.get("grant_token") or "").strip()

    if not token:
        return Response(
            {"ok": False, "error": "grant_token_required"},
            status=400,
        )

    try:
        payload = verify_grant_token(token)
    except jwt.ExpiredSignatureError:
        return Response(
            {"ok": False, "valid": False, "error": "token_expired"},
            status=403,
        )
    except jwt.InvalidTokenError:
        return Response(
            {"ok": False, "valid": False, "error": "invalid_token"},
            status=403,
        )

    return Response(
        {
            "ok": True,
            "valid": True,
            "payload": payload,
        },
        status=200,
    )
