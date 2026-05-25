from datetime import timedelta
from decimal import Decimal, InvalidOperation

from django.db import transaction
from django.http import HttpResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from .models import Subscription, PaymentEvent, PaymentTransaction


@csrf_exempt
def payfast_itn(request):
    if request.method != "POST":
        return HttpResponse("Method not allowed", status=405)

    m_payment_id = request.POST.get("m_payment_id")  # your Subscription.payment_reference
    payment_status = (request.POST.get("payment_status") or "").upper()
    pf_payment_id = request.POST.get("pf_payment_id")  # unique per PayFast payment
    amount_gross = request.POST.get("amount_gross")
    currency = (request.POST.get("currency") or "ZAR").upper()

    if not m_payment_id:
        return HttpResponse("Missing m_payment_id", status=400)

    sub = Subscription.objects.filter(payment_reference=m_payment_id).first()
    if not sub:
        return HttpResponse(
            f"Unknown subscription payment_reference: {m_payment_id}",
            status=400,
        )

    if payment_status == "COMPLETE":
        tx_status = "success"
    elif payment_status in {"FAILED", "CANCELLED"}:
        tx_status = "failed"
    else:
        tx_status = "pending"

    event_id = pf_payment_id or f"itn-{m_payment_id}"
    provider_txn_id = pf_payment_id or event_id

    try:
        amount = Decimal(amount_gross or "0.00")
    except (InvalidOperation, TypeError):
        return HttpResponse("Invalid amount_gross", status=400)

    now = timezone.now()

    with transaction.atomic():
        event, event_created = PaymentEvent.objects.get_or_create(
            event_id=event_id,
            defaults={
                "subscription": sub,
                "provider": "payfast",
                "event_type": "itn",
                "payload": dict(request.POST),
                "received_at": now,
            },
        )

        tx, tx_created = PaymentTransaction.objects.get_or_create(
            provider_txn_id=provider_txn_id,
            defaults={
                "subscription": sub,
                "amount": amount,
                "currency": currency,
                "status": tx_status,
                "paid_at": now if tx_status == "success" else None,
            },
        )

        # Prevent status regression and duplicate processing
        already_success = (not tx_created and tx.status == "success")

        if not tx_created:
            # Keep existing success immutable
            if tx.status != "success":
                tx.subscription = sub
                tx.amount = amount
                tx.currency = currency
                tx.status = tx_status
                if tx_status == "success" and not tx.paid_at:
                    tx.paid_at = now
                tx.save(update_fields=["subscription", "amount", "currency", "status", "paid_at"])

        # Only activate/extend once per successful payment
        should_extend = tx_status == "success" and not already_success and event_created

        if should_extend:
            anchor = sub.end_at if sub.end_at and sub.end_at > now else now
            sub.start_at = sub.start_at or now
            sub.end_at = anchor + timedelta(days=365)
            sub.status = Subscription.Status.ACTIVE
            sub.last_payment_at = now
            sub.save(update_fields=["start_at", "end_at", "status", "last_payment_at"])

    return HttpResponse("OK", status=200)
