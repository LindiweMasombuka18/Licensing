from datetime import timedelta

from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.utils import timezone

from licensing.models import Subscription, SubscriptionReminder


class Command(BaseCommand):
    help = "Send subscription renewal reminders (90/60/30 days before expiry)."

    def handle(self, *args, **options):
        now = timezone.now()
        schedule_days = [90, 60, 30]
        sent_count = 0

        for days in schedule_days:
            target_date = (now + timedelta(days=days)).date()

            subscriptions = Subscription.objects.select_related(
                "customer", "bundle"
            ).all()

            for sub in subscriptions:

                # Skip cancelled subscriptions
                if sub.status == Subscription.Status.CANCELLED:
                    continue

                end_date = sub.end_at.date()

                valid_dates = {
                    target_date - timedelta(days=1),
                    target_date,
                    target_date + timedelta(days=1),
                }

                if end_date not in valid_dates:
                    continue

                reminder_type = f"{days}_day"

                # Prevent duplicates
                if SubscriptionReminder.objects.filter(
                    subscription=sub,
                    reminder_type=reminder_type,
                ).exists():
                    continue

                to_email = sub.customer.billing_email

                subject = f"Subscription renewal reminder: {days} days remaining"
                message = (
                    f"Hello {sub.customer.company_name},\n\n"
                    f"Your subscription will expire in {days} days.\n\n"
                    f"Bundle: {sub.bundle.name}\n"
                    f"Expiry date: {sub.end_at.isoformat()}\n"
                    f"Grace ends: {sub.grace_end_at().isoformat()}\n\n"
                    f"Please renew to avoid service interruption.\n"
                )

                send_mail(
                    subject=subject,
                    message=message,
                    from_email=None,
                    recipient_list=[to_email],
                    fail_silently=False,
                )

                SubscriptionReminder.objects.create(
                    subscription=sub,
                    reminder_type=reminder_type,
                    sent_at=now,
                    email_to=to_email,
                )

                sent_count += 1
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Sent {reminder_type} reminder for subscription {sub.id}"
                    )
                )

        self.stdout.write(
            self.style.SUCCESS(f"Done. Total reminders sent: {sent_count}")
        )
