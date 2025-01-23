from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from .managers import UserManager
from django.utils import timezone


def user_profile_image_path(instance, filename):
    # File will be uploaded to MEDIA_ROOT/user_<id>/<filename>
    return f'user_{instance.id}/profile/{filename}'


def user_document_path(instance, filename):
    # File will be uploaded to MEDIA_ROOT/user_<id>/documents/<filename>
    return f'user_{instance.id}/documents/{filename}'


class CustomUser(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=200, unique=True)
    email = models.EmailField()
    first_name = models.CharField(max_length=200)
    last_name = models.CharField(max_length=200)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    role = models.CharField(max_length=200, default="user")
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)

    # Profile fields
    profile_image = models.ImageField(
        upload_to=user_profile_image_path,
        null=True,
        blank=True,
        help_text="Profile picture"
    )
    phone_number = models.CharField(max_length=15, null=True, blank=True)
    address = models.TextField(null=True, blank=True)

    # For drivers
    license_document = models.FileField(
        upload_to=user_document_path,
        null=True,
        blank=True,
        help_text="Driver's license document"
    )
    vehicle_registration = models.FileField(
        upload_to=user_document_path,
        null=True,
        blank=True,
        help_text="Vehicle registration document"
    )

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'first_name', 'last_name']

    objects = UserManager()

    def __str__(self):
        return self.username

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

    def get_short_name(self):
        return self.first_name

    def get_profile_image_url(self):
        if self.profile_image:
            return self.profile_image.url
        return None


class UserSession(models.Model):
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='sessions')
    token = models.CharField(max_length=255)  # Store the refresh token hash
    device_type = models.CharField(max_length=50)  # mobile, desktop, tablet
    browser = models.CharField(max_length=50)
    ip_address = models.GenericIPAddressField()
    location = models.CharField(max_length=100, null=True, blank=True)
    last_activity = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    # New security fields
    user_agent = models.TextField(
        null=True, blank=True)  # Full user agent string
    os_info = models.CharField(
        max_length=100, null=True, blank=True)  # Operating system info
    login_successful = models.BooleanField(default=True)  # Track login success
    login_attempts = models.IntegerField(
        default=0)  # Track failed login attempts
    last_failed_attempt = models.DateTimeField(
        null=True, blank=True)  # Last failed login attempt
    is_suspicious = models.BooleanField(
        default=False)  # Flag for suspicious activity
    # Notes about security concerns
    security_notes = models.TextField(null=True, blank=True)

    class Meta:
        ordering = ['-last_activity']

    def __str__(self):
        return f"{self.user.username} - {self.device_type} - {self.browser}"

    def mark_suspicious(self, reason):
        self.is_suspicious = True
        current_notes = self.security_notes or ''
        self.security_notes = f"{timezone.now()}: {reason}\n{current_notes}"
        self.save()

    def record_login_attempt(self, successful):
        if not successful:
            self.login_attempts += 1
            self.last_failed_attempt = timezone.now()
            if self.login_attempts >= 5:  # Mark suspicious after 5 failed attempts
                self.mark_suspicious("Multiple failed login attempts")
        else:
            self.login_successful = True
            self.login_attempts = 0
        self.save()
