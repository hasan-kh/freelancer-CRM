"""Serializers for account app."""
from datetime import datetime
import logging

from django.contrib.auth import password_validation

from rest_framework import serializers

from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer
)

from utils.error_handling import ErrorCodes, ValidationDetails


# Configure the logger
logger = logging.getLogger('django')


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """My Custom ObtainPairSerializer witch includes expire date times."""
    def validate(self, attrs):
        data = super().validate(attrs)

        refresh = self.get_token(self.user)

        # Add custom response data
        data['refresh_expires_at'] = datetime.fromtimestamp(refresh['exp'])
        data['access_expires_at'] = datetime.fromtimestamp(refresh.access_token['exp'])

        return data


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    """My Custom TokenRefreshSerializer witch includes expire date times."""

    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.token_class(attrs["refresh"])

        # Add custom response data
        data['refresh_expires_at'] = datetime.fromtimestamp(refresh['exp'])
        data['access_expires_at'] = datetime.fromtimestamp(refresh.access_token['exp'])

        return data


class UserChangePasswordSerializer(serializers.Serializer):
    """User Change Password Serializer."""
    password = serializers.CharField(write_only=True,
                                     trim_whitespace=False,
                                     style={'input_type': 'password'})
    new_password1 = serializers.CharField(write_only=True,
                                          trim_whitespace=False,
                                          style={'input_type': 'password'},
                                          max_length=128)
    new_password2 = serializers.CharField(write_only=True,
                                          trim_whitespace=False,
                                          style={'input_type': 'password'},
                                          max_length=128)

    def validate_password(self, value):
        """Validate current password."""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(
                detail=ValidationDetails.PASSWORD_INCORRECT,
                code=ErrorCodes.PASSWORD_INCORRECT
            )
        return value

    def validate_new_password1(self, value):
        """Validate new password's strength."""
        user = self.context['request'].user
        try:
            password_validation.validate_password(value, user=user)
        except serializers.ValidationError as e:
            raise serializers.ValidationError(
                {'new_password1': e.messages}
            )
        return value

    def validate(self, attrs):
        """Validate current and new passwords."""
        password = attrs.get('password', False)
        new_password1 = attrs.get('new_password1', False)
        new_password2 = attrs.get('new_password2', False)

        # Check all fields available
        if not all([password, new_password1, new_password2]):
            raise serializers.ValidationError(
                detail=ValidationDetails.REQUIRED_FIELDS,
                code=ErrorCodes.REQUIRED_FIELDS,
            )

        # Check new passwords match
        if new_password1 != new_password2:
            raise serializers.ValidationError(
                detail=ValidationDetails.PASSWORDS_DO_NOT_MATCH,
                code=ErrorCodes.PASSWORDS_DO_NOT_MATCH,
            )
        return attrs

    def save(self, **kwargs):
        """Change the password."""
        user = self.context['request'].user
        new_password = self.validated_data['new_password1']
        user.set_password(new_password)
        user.save()
        logger.info('User (ID: %d) changed password.', user.id)
        return user
