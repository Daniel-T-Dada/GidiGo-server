from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, action, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken
from drf_yasg.utils import swagger_auto_schema
from django.contrib.auth import authenticate, get_user_model
from .serializers import (
    UserSerializer,
    LoginSerializer,
    LogoutSerializer,
    UserUpdateSerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
    UserSessionSerializer
)
from django.conf import settings
import pusher
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
import hashlib
from user_agents import parse
from .models import UserSession
from django.utils import timezone
from datetime import timedelta

User = get_user_model()

# Initialize Pusher if settings are valid
try:
    pusher_client = pusher.Pusher(
        app_id=settings.PUSHER_APP_ID,
        key=settings.PUSHER_KEY,
        secret=settings.PUSHER_SECRET,
        cluster=settings.PUSHER_CLUSTER,
        ssl=True
    )
except Exception as e:
    print(f"Warning: Pusher initialization failed - {str(e)}")
    pusher_client = None


class CreateUserView(APIView):
    @swagger_auto_schema(
        operation_description="Create a new user account",
        request_body=UserSerializer,
        responses={201: UserSerializer()}
    )
    @action(detail=True, methods=['post'])
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()  # create method is called internally

        # Generate tokens
        refresh_token = RefreshToken.for_user(user)
        token_hash = hashlib.sha256(str(refresh_token).encode()).hexdigest()

        # Get device info
        user_agent_string = request.META.get('HTTP_USER_AGENT', '')
        user_agent = parse(user_agent_string)
        device_type = 'mobile' if user_agent.is_mobile else 'tablet' if user_agent.is_tablet else 'desktop'
        ip_address = request.META.get('REMOTE_ADDR')

        # Get browser and OS info
        browser_string = format_browser_string(user_agent)
        os_string = format_os_string(user_agent)

        # Create session
        session = create_user_session(
            user, token_hash, device_type, user_agent, ip_address, user_agent_string)

        # Return user data and tokens
        return Response({
            'id': user.pk,
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'role': user.role,
            'access_token': str(refresh_token.access_token),
            'refresh_token': str(refresh_token)
        }, status=201)


class LoginView(APIView):
    @swagger_auto_schema(
        operation_description="Login with username and password",
        request_body=LoginSerializer
    )
    @action(detail=True, methods=['post'])
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(
                request,
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password']
            )

            # Get device info
            user_agent_string = request.META.get('HTTP_USER_AGENT', '')
            user_agent = parse(user_agent_string)
            device_type = 'mobile' if user_agent.is_mobile else 'tablet' if user_agent.is_tablet else 'desktop'
            ip_address = request.META.get('REMOTE_ADDR')

            # Check for existing session from this device
            existing_session = None
            if user:
                existing_session = UserSession.objects.filter(
                    user=user,
                    device_type=device_type,
                    browser=format_browser_string(user_agent),
                    ip_address=ip_address,
                    is_active=True
                ).first()

            if user and not user.is_active:
                return Response(
                    {"error": "Account is disabled"},
                    status=401
                )

            if user:
                try:
                    refresh_token = RefreshToken.for_user(user)
                    token_hash = hashlib.sha256(
                        str(refresh_token).encode()).hexdigest()

                    # Update existing session or create new one
                    if existing_session:
                        existing_session.token = token_hash
                        existing_session.last_activity = timezone.now()
                        existing_session.login_successful = True
                        existing_session.login_attempts = 0
                        existing_session.save()
                        session = existing_session
                    else:
                        session = create_user_session(
                            user, token_hash, device_type, user_agent, ip_address, user_agent_string)

                    # Check for suspicious activity
                    recent_failed_attempts = UserSession.objects.filter(
                        user=user,
                        login_successful=False,
                        last_failed_attempt__gte=timezone.now() - timedelta(hours=1)
                    ).count()

                    if recent_failed_attempts >= 5:
                        session.mark_suspicious(
                            "Multiple failed login attempts across devices")

                    # Check for multiple locations
                    active_sessions = UserSession.objects.filter(
                        user=user,
                        is_active=True
                    ).exclude(id=session.id)

                    if active_sessions.exists():
                        distinct_ips = set(
                            active_sessions.values_list('ip_address', flat=True))
                        if len(distinct_ips) >= 3:  # More than 3 different IPs
                            session.mark_suspicious(
                                "Multiple logins from different locations")

                    return Response({
                        'id': user.pk,
                        'username': user.username,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'email': user.email,
                        'role': user.role,
                        'access_token': str(refresh_token.access_token),
                        'refresh_token': str(refresh_token)
                    }, status=200)

                except Exception as error:
                    return Response(
                        {"error": f"Token generation failed: {str(error)}"},
                        status=400
                    )
            else:
                # Record failed login attempt
                if 'username' in serializer.validated_data:
                    try:
                        attempted_user = User.objects.get(
                            username=serializer.validated_data['username'])
                        session = UserSession.objects.filter(
                            user=attempted_user,
                            device_type=device_type,
                            browser=format_browser_string(user_agent),
                            ip_address=ip_address
                        ).first()

                        if session:
                            session.record_login_attempt(successful=False)
                        else:
                            UserSession.objects.create(
                                user=attempted_user,
                                device_type=device_type,
                                browser=format_browser_string(user_agent),
                                ip_address=ip_address,
                                user_agent=user_agent_string,
                                os_info=format_os_string(user_agent),
                                login_successful=False,
                                login_attempts=1,
                                last_failed_attempt=timezone.now()
                            )
                    except User.DoesNotExist:
                        pass

                return Response(
                    {"error": "Invalid login credentials"},
                    status=401
                )
        return Response(
            {"error": serializer.errors},
            status=400
        )


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Logout and blacklist the refresh token",
        request_body=LogoutSerializer,
        responses={
            200: "{'message': 'Logout successful'}",
            401: "{'error': 'Authentication credentials were not provided'}",
            400: "{'error': 'Failed to blacklist token'}"
        }
    )
    def post(self, request):
        try:
            serializer = LogoutSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            token = RefreshToken(serializer.validated_data['refresh_token'])
            token_hash = hashlib.sha256(str(token).encode()).hexdigest()

            # Deactivate the session
            UserSession.objects.filter(
                user=request.user,
                token=token_hash
            ).update(is_active=False)

            token.blacklist()

            return Response(
                {"message": "Logout successful"},
                status=200
            )
        except Exception as error:
            return Response(
                {"error": str(error)},
                status=400
            )


class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get user profile information",
        responses={200: UserSerializer()}
    )
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_description="Update user profile information",
        request_body=UserUpdateSerializer,
        responses={200: UserUpdateSerializer()}
    )
    def patch(self, request):
        serializer = UserUpdateSerializer(
            request.user,
            data=request.data,
            partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def pusher_auth(request):
    """
    Authenticate private channels for Pusher
    """
    print("Pusher auth request received")  # Debug log

    if not pusher_client:
        print("Pusher client not configured")  # Debug log
        return Response(
            {"error": "Pusher is not configured"},
            status=503
        )

    socket_id = request.data.get('socket_id')
    channel_name = request.data.get('channel_name')

    print(f"Auth request for socket_id: {socket_id}, channel: {channel_name}")  # Debug log

    if not socket_id or not channel_name:
        print("Missing socket_id or channel_name")  # Debug log
        return Response(
            {"error": "Missing socket_id or channel_name"},
            status=400
        )

    # For private channels
    if channel_name.startswith('private-'):
        try:
            auth = pusher_client.authenticate(
                channel=channel_name,
                socket_id=socket_id,
                custom_data={
                    'user_id': request.user.id,
                    'user_info': {
                        'username': request.user.username,
                        'role': request.user.role
                    }
                }
            )
            print(f"Successfully authenticated channel for user: {request.user.username}")  # Debug log
            return Response(auth)
        except Exception as e:
            print(f"Pusher authentication failed: {str(e)}")  # Debug log
            return Response(
                {"error": f"Pusher authentication failed: {str(e)}"},
                status=500
            )

    print("Not a private channel")  # Debug log
    return Response({"error": "Not a private channel"}, status=400)


class PasswordResetView(APIView):
    @swagger_auto_schema(
        operation_description="Request password reset email",
        request_body=PasswordResetSerializer,
        responses={200: "{'message': 'Password reset email sent'}"}
    )
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
                # Generate password reset token
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))

                # Send password reset email
                frontend_url = settings.FRONTEND_URL.rstrip('/')
                reset_url = f"{frontend_url}/reset-password/{uid}/{token}"
                email_content = f'Click the following link to reset your password: {reset_url}'
                send_mail(
                    'Reset your password',
                    email_content,
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                    fail_silently=False,
                )
                return Response(
                    {"message": "Password reset email sent"},
                    status=200
                )
            except User.DoesNotExist:
                # Return success even if user doesn't exist for security
                return Response(
                    {"message": "Password reset email sent"},
                    status=200
                )
        return Response(serializer.errors, status=400)


class PasswordResetConfirmView(APIView):
    @swagger_auto_schema(
        operation_description="Confirm password reset with token",
        request_body=PasswordResetConfirmSerializer,
        responses={200: "{'message': 'Password reset successful'}"}
    )
    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"error": "Invalid reset link"},
                status=400
            )

        if default_token_generator.check_token(user, token):
            serializer = PasswordResetConfirmSerializer(data=request.data)
            if serializer.is_valid():
                user.set_password(serializer.validated_data['password'])
                user.save()
                return Response(
                    {"message": "Password reset successful"},
                    status=200
                )
            return Response(serializer.errors, status=400)
        return Response(
            {"error": "Invalid or expired reset link"},
            status=400
        )


class UserSessionView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Get all active sessions for the current user",
        responses={200: UserSessionSerializer(many=True)}
    )
    def get(self, request):
        sessions = UserSession.objects.filter(
            user=request.user,
            is_active=True
        )
        serializer = UserSessionSerializer(sessions, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_description="Terminate specific session",
        responses={200: "{'message': 'Session terminated successfully'}"}
    )
    def delete(self, request, session_id=None):
        if session_id:
            # Terminate specific session
            session = UserSession.objects.filter(
                id=session_id,
                user=request.user
            ).first()

            if not session:
                return Response(
                    {"error": "Session not found"},
                    status=404
                )

            session.is_active = False
            session.save()

            return Response(
                {"message": "Session terminated successfully"},
                status=200
            )
        else:
            # Terminate all sessions except current
            current_token = request.auth
            if current_token:
                current_token_hash = hashlib.sha256(
                    str(RefreshToken(current_token)).encode()
                ).hexdigest()

                UserSession.objects.filter(
                    user=request.user
                ).exclude(
                    token=current_token_hash
                ).update(is_active=False)

                return Response(
                    {"message": "All other sessions terminated successfully"},
                    status=200
                )

            return Response(
                {"error": "Current session not found"},
                status=400
            )


@api_view(['GET'])
def check_environment(request):
    if settings.DEBUG:  # Only show this in development
        return Response({
            'environment': 'Development' if settings.DEBUG else 'Production',
            'secret_key_length': len(settings.SECRET_KEY),
            'debug_mode': settings.DEBUG,
        })
    return Response({'message': 'Not available in production'})


def format_browser_string(user_agent):
    """Helper function to format browser string"""
    return f"{user_agent.browser.family} {user_agent.browser.version_string}"


def format_os_string(user_agent):
    """Helper function to format OS string"""
    return f"{user_agent.os.family} {user_agent.os.version_string}"


def create_user_session(user, token_hash, device_type, user_agent, ip_address, user_agent_string, login_successful=True):
    """Helper function to create user session"""
    return UserSession.objects.create(
        user=user,
        token=token_hash,
        device_type=device_type,
        browser=format_browser_string(user_agent),
        ip_address=ip_address,
        user_agent=user_agent_string,
        os_info=format_os_string(user_agent),
        login_successful=login_successful
    )
