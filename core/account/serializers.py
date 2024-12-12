"""Serializers for account app."""
from datetime import datetime

from django.conf import settings
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.password_validation import validate_password as dj_validate_password

from rest_framework import serializers

from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer
)

from account.models import PasswordResetCode
from utils.error_handling import MyErrors
from utils.custom_logging import user_action_logger, get_ip_from_request


class GenericSuccessSerializer(serializers.Serializer):
    """Generic success serializer which has only a detail message."""
    detail = serializers.CharField(help_text='A success message')


class CustomTokenObtainPairRequestSerializer(serializers.Serializer):
    """Custom token obtain pair request serializer."""
    email = serializers.EmailField(max_length=254)
    password = serializers.CharField(max_length=128,
                                     write_only=True,
                                     trim_whitespace=False,
                                     style={'input_type': 'password'})

    def validate_email(self, value):
        """Validate email exists and related account is active."""
        request = self.context['request']
        # Check account with provided Email exists
        try:
            user = get_user_model().objects.get(email=value)
        except get_user_model().DoesNotExist:
            user_action_logger.warning(f'Login failed, email({value}) not found.', extra={
                'user_id': 'Anonymous',
                'client_ip': get_ip_from_request(request)
            })
            raise serializers.ValidationError(  # pylint: disable=raise-missing-from
                detail=MyErrors.USER_EMAIL_NOT_FOUND['detail'].format(email=value),
                code=MyErrors.USER_EMAIL_NOT_FOUND['code'],
            )

        # Check related account is active
        if not user.is_active:
            user_action_logger.warning(f'Login failed, user({value}) is inactive.', extra={
                'user_id': user.id,
                'client_ip': get_ip_from_request(request)
            })
            raise serializers.ValidationError(
                detail=MyErrors.USER_INACTIVE['detail'].format(email=value),
                code=MyErrors.USER_INACTIVE['code'],
            )

        return value

    def validate(self, attrs):
        request = self.context['request']

        # Authenticate user
        user = authenticate(request, email=attrs['email'], password=attrs['password'])
        if not user:
            user_action_logger.warning(f'Login failed, incorrect credentials({attrs["email"]}).', extra={
                'user_id': 'Anonymous',
                'client_ip': get_ip_from_request(request)
            })
            raise serializers.ValidationError(
                detail=MyErrors.INCORRECT_CREDENTIALS['detail'],
                code=MyErrors.INCORRECT_CREDENTIALS['code'],
            )

        return attrs


# class CustomTokenObtainPairResponseSerializer(serializers.Serializer):
#     """
#     Serializer for response of the CustomTokenObtainPairView
#     """
#     refresh = serializers.CharField()
#     access = serializers.CharField()
#     refresh_expires_at = serializers.CharField()
#     access_expires_at = serializers.CharField()


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """My Custom ObtainPairSerializer witch includes expire date times."""
    def validate(self, attrs):
        data = super().validate(attrs)

        refresh = self.get_token(self.user)

        # Add custom response data
        data['refresh_expires_at'] = str(datetime.fromtimestamp(refresh['exp']))
        data['access_expires_at'] = str(datetime.fromtimestamp(refresh.access_token['exp']))

        return data


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    """My Custom TokenRefreshSerializer witch includes expire date times."""

    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.token_class(attrs["refresh"])

        # # Check if related user is active
        # user_id = refresh.payload['user_id']
        # try:
        #     user = get_user_model().objects.get(id=user_id, is_active=True)
        # except get_user_model().DoesNotExist:
        #     raise serializers.ValidationError(
        #         detail=MyErrors.USER_INACTIVE['detail'].format(email='N/A'),
        #         code=MyErrors.USER_INACTIVE['code'],
        #     )

        # Add custom response data
        data['access_expires_at'] = str(datetime.fromtimestamp(refresh.access_token['exp']))

        return data


class ChangePasswordSerializer(serializers.Serializer):
    """User Change Password Serializer."""
    password = serializers.CharField(write_only=True,
                                     trim_whitespace=False,
                                     style={'input_type': 'password'})
    new_password1 = serializers.CharField(write_only=True,
                                          trim_whitespace=False,
                                          style={'input_type': 'password'},
                                          max_length=128,
                                          validators=[dj_validate_password])
    new_password2 = serializers.CharField(write_only=True,
                                          trim_whitespace=False,
                                          style={'input_type': 'password'},
                                          max_length=128)

    def validate_password(self, value):
        """Validate current password."""
        request = self.context['request']
        if not request.user.check_password(value):
            user_action_logger.warning('Change password fails, incorrect current password.',
                                       extra={'user_id': request.user.id,
                                              'client_ip': get_ip_from_request(request)})
            raise serializers.ValidationError(
                detail=MyErrors.PASSWORD_INCORRECT['detail'],
                code=MyErrors.PASSWORD_INCORRECT['code']
            )
        return value

    def validate(self, attrs):
        """Validate current and new passwords."""
        request = self.context['request']
        password = attrs.get('password', False)
        new_password1 = attrs.get('new_password1', False)
        new_password2 = attrs.get('new_password2', False)

        # Check all fields available
        if not all([password, new_password1, new_password2]):
            raise serializers.ValidationError(
                detail=MyErrors.REQUIRED_FIELDS['detail'],
                code=MyErrors.REQUIRED_FIELDS['code'],
            )

        # Check new passwords match
        if new_password1 != new_password2:
            user_action_logger.warning('Change password fails, new passwords do not match.',
                                       extra={'user_id': request.user.id,
                                              'client_ip': get_ip_from_request(request)})
            raise serializers.ValidationError(
                detail=MyErrors.PASSWORDS_DO_NOT_MATCH['detail'],
                code=MyErrors.PASSWORDS_DO_NOT_MATCH['code'],
            )
        return attrs


class PasswordResetRequestSerializer(serializers.Serializer):
    """Serializer for password reset request."""
    email = serializers.EmailField(max_length=254)

    def validate_email(self, value):
        """Validate email exists and related account is active."""
        request = self.context['request']
        # Check email exists
        try:
            user = get_user_model().objects.get(email=value)
        except get_user_model().DoesNotExist:

            user_action_logger.warning(f'Password reset fails, account with email({value}) not found.',
                                       extra={'user_id': 'Anonymous',
                                              'client_ip': get_ip_from_request(request)})
            raise serializers.ValidationError(  # pylint: disable=raise-missing-from
                detail=MyErrors.USER_EMAIL_NOT_FOUND['detail'].format(email=value),
                code=MyErrors.USER_EMAIL_NOT_FOUND['code'],
            )

        if not user.is_active:
            user_action_logger.warning(f'Password reset fails, account with email({value}) is inactive.',
                                       extra={'user_id': 'Anonymous',
                                              'client_ip': get_ip_from_request(request)})

            raise serializers.ValidationError(
                detail=MyErrors.USER_INACTIVE['detail'].format(email=value),
                code=MyErrors.USER_INACTIVE['code'],
            )

        return value


class PasswordResetSerializer(serializers.Serializer):
    """Serializer for password reset."""
    code = serializers.CharField(max_length=settings.PASSWORD_RESET_CODE_LENGTH)
    new_password1 = serializers.CharField(write_only=True,
                                          trim_whitespace=False,
                                          style={'input_type': 'password'},
                                          max_length=128,
                                          validators=[dj_validate_password])
    new_password2 = serializers.CharField(write_only=True,
                                          trim_whitespace=False,
                                          style={'input_type': 'password'},
                                          max_length=128)

    def validate_code(self, value):
        """Validate code is not expired."""
        # get PasswordResetCode object
        request = self.context['request']
        try:
            prc = PasswordResetCode.objects.get(code=value)
        except PasswordResetCode.DoesNotExist:
            user_action_logger.warning('Password reset fails, code does not exist.',
                                       extra={'user_id': 'Anonymous',
                                              'client_ip': get_ip_from_request(request)})

            raise serializers.ValidationError(  # pylint: disable=raise-missing-from
                detail=MyErrors.CODE_INVALID['detail'],
                code=MyErrors.CODE_INVALID['code'],
            )

        # Check code is not expired
        if prc.is_expired():
            user_action_logger.warning(f'Password reset fails, code({prc.code}) is expired.',
                                       extra={'user_id': 'Anonymous',
                                              'client_ip': get_ip_from_request(request)})
            raise serializers.ValidationError(
                detail=MyErrors.CODE_EXPIRED['detail'],
                code=MyErrors.CODE_EXPIRED['code'],
            )
        return value

    def validate(self, attrs):
        """Validate current and new passwords."""
        request = self.context['request']
        code = attrs.get('code', False)
        new_password1 = attrs.get('new_password1', False)
        new_password2 = attrs.get('new_password2', False)

        # Check all fields available
        if not all([code, new_password1, new_password2]):
            raise serializers.ValidationError(
                detail=MyErrors.REQUIRED_FIELDS['detail'],
                code=MyErrors.REQUIRED_FIELDS['code'],
            )

        # Check new passwords match
        if new_password1 != new_password2:
            user_action_logger.warning('Password reset fails, new passwords do not match.',
                                       extra={'user_id': 'Anonymous',
                                              'client_ip': get_ip_from_request(request)})
            raise serializers.ValidationError(
                detail=MyErrors.PASSWORDS_DO_NOT_MATCH['detail'],
                code=MyErrors.PASSWORDS_DO_NOT_MATCH['code'],
            )
        return attrs


class RegisterSerializer(serializers.ModelSerializer):
    """User register serializer."""
    password_repeat = serializers.CharField(write_only=True,
                                            trim_whitespace=False,
                                            style={'input_type': 'password'},
                                            max_length=128)

    class Meta:
        model = get_user_model()
        fields = ('id', 'email', 'password', 'password_repeat',
                  'first_name', 'last_name', 'cellphone')
        extra_kwargs = {'password': {'write_only': True, 'validators': [dj_validate_password]},
                        'first_name': {'required': True},
                        'last_name': {'required': True},
                        'cellphone': {'required': True,
                                      'help_text': 'Cellphone must be 11 digits long and '
                                                   'starts with 09.'},
                        }
        read_only_fields = ('id',)

    def validate(self, attrs):
        """Validate password and password_retry."""
        request = self.context['request']
        password = attrs.get('password', False)
        password_repeat = attrs.get('password_repeat', False)

        # Check new passwords match
        if password != password_repeat:
            user_action_logger.warning('User register fails, passwords do not match.',
                                       extra={'user_id': 'Anonymous',
                                              'client_ip': get_ip_from_request(request)})
            raise serializers.ValidationError(
                detail=MyErrors.PASSWORDS_DO_NOT_MATCH['detail'],
                code=MyErrors.PASSWORDS_DO_NOT_MATCH['code'],
            )
        return attrs

    def create(self, validated_data):
        # password_repeat is not part of User model
        validated_data.pop('password_repeat')
        # Create user
        return get_user_model().objects.create_user(**validated_data)


class ManageUserSerializer(serializers.ModelSerializer):
    """Serializer for retrieve and update authenticated user."""

    class Meta:
        model = get_user_model()
        fields = ('id', 'email', 'first_name', 'last_name', 'cellphone')
        read_only_fields = ('id',)
        extra_kwargs = {
            'email': {'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True},
            'cellphone': {'required': True, 'help_text': 'Cellphone must be 11 digits long and '
                                            'starts with 09.'},
        }
