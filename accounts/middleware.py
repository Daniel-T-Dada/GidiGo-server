from django.utils import timezone
from django.conf import settings
from django.core.exceptions import PermissionDenied
from rest_framework_simplejwt.tokens import AccessToken
from .models import UserSession
import hashlib


class SessionActivityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip middleware for non-authenticated requests
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return self.get_response(request)

        # Get the current token
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                # Get token hash
                token_hash = hashlib.sha256(token.encode()).hexdigest()

                # Update session activity
                session = UserSession.objects.filter(
                    user=request.user,
                    token=token_hash,
                    is_active=True
                ).first()

                if session:
                    # Check session timeout
                    inactive_time = (timezone.now() -
                                     session.last_activity).total_seconds()
                    if inactive_time > settings.INACTIVE_SESSION_TIMEOUT:
                        session.is_active = False
                        session.save()
                        raise PermissionDenied(
                            'Session expired due to inactivity')

                    # Update last activity
                    session.last_activity = timezone.now()
                    session.save()

                    # Enforce maximum sessions per user
                    active_sessions = UserSession.objects.filter(
                        user=request.user,
                        is_active=True
                    ).order_by('-last_activity')

                    if active_sessions.count() > settings.MAX_SESSIONS_PER_USER:
                        # Keep the most recent sessions and deactivate others
                        sessions_to_deactivate = active_sessions[settings.MAX_SESSIONS_PER_USER:]
                        for old_session in sessions_to_deactivate:
                            old_session.is_active = False
                            old_session.save()

            except Exception as e:
                print(f"Session activity error: {str(e)}")

        response = self.get_response(request)
        return response
