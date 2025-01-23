from django.core.management.base import BaseCommand
from django.utils import timezone
from django.conf import settings
from accounts.models import UserSession
from datetime import timedelta


class Command(BaseCommand):
    help = 'Clean up expired user sessions'

    def handle(self, *args, **kwargs):
        # Calculate expiry time
        expiry_time = timezone.now() - timedelta(hours=settings.SESSION_EXPIRY_HOURS)

        # Get expired sessions
        expired_sessions = UserSession.objects.filter(
            last_activity__lt=expiry_time,
            is_active=True
        )

        # Count expired sessions
        expired_count = expired_sessions.count()

        # Deactivate expired sessions
        expired_sessions.update(is_active=False)

        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully deactivated {expired_count} expired sessions'
            )
        )
