from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import UserSession


User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    re_password = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True,
        required=True
    )
    password = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True
    )

    class Meta:
        model = User
        fields = [
            'username',
            'password',
            're_password',
            'email',
            'first_name',
            'last_name',
            'role',
            'phone_number'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            're_password': {'write_only': True},
            'role': {'required': True}
        }

    def validate(self, attrs):
        # Remove re_password from attrs since we don't want to save it
        re_password = attrs.pop('re_password', None)
        password = attrs.get('password', None)

        if not password or len(password) < 8:
            raise serializers.ValidationError(
                {"password": "Password must be at least 8 characters"}
            )

        if password != re_password:
            raise serializers.ValidationError(
                {"password": "Passwords do not match"}
            )

        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=200)
    password = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True
    )


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(max_length=1000)


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
        # These fields shouldn't be updated via this serializer
        read_only_fields = ['username', 'role']


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    password = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True
    )
    re_password = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True
    )

    def validate(self, attrs):
        password = attrs.get('password')
        re_password = attrs.get('re_password')

        if not password or len(password) < 8:
            raise serializers.ValidationError(
                {"password": "Password must be at least 8 characters"}
            )

        if password != re_password:
            raise serializers.ValidationError(
                {"password": "Passwords do not match"}
            )

        return attrs


class UserSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSession
        fields = [
            'id',
            'device_type',
            'browser',
            'ip_address',
            'location',
            'last_activity',
            'created_at',
            'is_active'
        ]
        read_only_fields = fields
