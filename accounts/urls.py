from django.urls import path
from rest_framework_simplejwt.views import (
    TokenVerifyView,
    TokenRefreshView
)
from .views import (
    CreateUserView,
    LoginView,
    LogoutView,
    UserProfileView,
    pusher_auth,
    PasswordResetView,
    PasswordResetConfirmView,
    UserSessionView,
    check_environment
)

app_name = 'accounts'

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', CreateUserView.as_view(), name='register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),

    # Password reset endpoints
    path('auth/password/reset/', PasswordResetView.as_view(), name='password-reset'),
    path('auth/password/reset/confirm/<str:uidb64>/<str:token>/',
         PasswordResetConfirmView.as_view(), name='password-reset-confirm'),

    # Token endpoints
    path('auth/token/verify/', TokenVerifyView.as_view(), name='token-verify'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),

    # Profile endpoints
    path('auth/profile/', UserProfileView.as_view(), name='profile'),

    # Session management endpoints
    path('auth/sessions/', UserSessionView.as_view(), name='sessions-list'),
    path('auth/sessions/<int:session_id>/',
         UserSessionView.as_view(), name='session-detail'),

    # Pusher authentication
    path('auth/pusher/auth/', pusher_auth, name='pusher-auth'),

    # New URL pattern
    path('check-environment/', check_environment, name='check-environment'),
]
