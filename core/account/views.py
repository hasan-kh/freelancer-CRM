"""Views for accounts app."""
from datetime import datetime

from django.contrib.auth import get_user_model
from django.utils.translation import gettext as _

from rest_framework import status, serializers
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView, CreateAPIView, RetrieveUpdateAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.request import Request
from rest_framework.response import Response

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView, TokenBlacklistView

from drf_spectacular.utils import extend_schema, OpenApiExample, extend_schema_view, OpenApiResponse, inline_serializer

from utils.error_handling import ErrorResponseSerializer
from utils.tasks import (
    task_change_password_mail,
    task_password_reset_request_mail,
)
from utils.custom_logging import user_action_logger
from utils.functions import get_ip_from_request
from account.models import PasswordResetCode
from account.serializers import (
    CustomTokenObtainPairRequestSerializer,
    GenericSuccessSerializer,
    ChangePasswordSerializer,
    PasswordResetRequestSerializer,
    PasswordResetSerializer,
    RegisterSerializer,
    ManageUserSerializer,
)


GenericOpenApiResponse400 = OpenApiResponse(
    description='Validation error occurred.Errors contain keys for '
    '`field name` (which means validation error raised for a certain field) or '
    '`non_field_errors` for errors that are not tied to a single field.',
    response=ErrorResponseSerializer,
)

GenericOpenApiResponse401 = OpenApiResponse(
    description='Not authorized: invalid or expired token or not including authorization header.',
)


class CustomTokenObtainPairView(APIView):
    """
    Custom implementation of the TokenObtainPairView with defining serializers and additional data.
    """

    @extend_schema(
        summary='Authenticate user (JWT Token)',
        description='Authenticate user using provided credentials.',
        tags=['Account'],
        request=CustomTokenObtainPairRequestSerializer,
        responses={
            200: OpenApiResponse(
                description='Authentication successful.',
                response=inline_serializer(
                    name='LoginSerializer',
                    fields={
                        'refresh': serializers.CharField(),
                        'access': serializers.CharField(),
                        'refresh_expires_at': serializers.CharField(),
                        'access_expires_at': serializers.CharField(),
                    },
                ),
                examples=[
                    OpenApiExample(
                        name='Success',
                        value={
                            'refresh': 'Refresh token here',
                            'access': 'Access token here',
                            'refresh_expires_at': '2024-11-30 13:23:25',
                            'access_expires_at': '2024-11-29 14:23:25',
                        },
                    )
                ],
            ),
            400: GenericOpenApiResponse400,
        }
    )
    def post(self, request):
        serializer = CustomTokenObtainPairRequestSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        # If serializer is valid then user authenticated correctly, get user object
        user = get_user_model().objects.get(email=serializer.validated_data['email'])

        # Generate tokens
        refresh = RefreshToken.for_user(user)

        # My Custom response
        response_data = {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "refresh_expires_at": str(datetime.fromtimestamp(refresh['exp'])),
            "access_expires_at": str(datetime.fromtimestamp(refresh.access_token['exp']))
        }
        user_action_logger.info('User logged in.', extra={'user_id': user.id,
                                                          'client_ip': get_ip_from_request(request)})
        return Response(response_data, status=status.HTTP_200_OK)


class CustomTokenBlacklistView(TokenBlacklistView):
    """
    Custom implementation of the TokenBlacklistView Just to define documentation.
    """
    @extend_schema(
        summary='Logout',
        description='Add refresh token to Black list.',
        tags=['Account'],
        request=inline_serializer(
            name='TokenBlackListSerializer',
            fields={
                'refresh': serializers.CharField()
            },
        ),
        responses={
            200: OpenApiResponse(
                description='Token black listed successfully.',
            ),
            400: GenericOpenApiResponse400,
            401: OpenApiResponse(
                description='Invalid, expired or black listed refresh token.'
            )
        },
    )
    def post(self, request: Request, *args, **kwargs) -> Response:
        return super().post(request, *args, **kwargs)


class CustomTokenRefreshView(TokenRefreshView):
    """
    Custom implementation of the TokenRefreshView which includes access token and access_expires_at fields.
    """
    @extend_schema(
        summary='Refresh access token.',
        description='Refresh access token by posting valid and not expired refresh token.',
        tags=['Account'],
        request=inline_serializer(
            name='TokenRefreshSerializer',
            fields={
                'refresh': serializers.CharField()
            },
        ),
        responses={
            200: OpenApiResponse(
                description='Token refresh successful.',
                response=inline_serializer(
                    name='TokenRefreshResponseSerializer',
                    fields={
                        'access': serializers.CharField(),
                        'access_expires_at': serializers.CharField(),
                    },
                ),
                examples=[
                    OpenApiExample(
                        name='Success',
                        value={
                            'access': 'Access token here',
                            'access_expires_at': '2024-11-29 14:23:25',
                        },
                    )
                ],
            ),
            400: GenericOpenApiResponse400,
            401: OpenApiResponse(
                description='Invalid, expired or black listed refresh token.'
            )
        },
    )
    def post(self, request: Request, *args, **kwargs) -> Response:
        response = super().post(request, *args, **kwargs)
        return response


class ChangePasswordView(GenericAPIView):
    """Update user password after confirm current password."""
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    @extend_schema(
        summary='Change authenticated user password.',
        description='Confirm authenticated user current password then change it.',
        tags=['Account Password Management'],
        request=ChangePasswordSerializer,
        responses={
            200: OpenApiResponse(
                description='Password changed successfully.',
                response=GenericSuccessSerializer,
                examples=[
                    OpenApiExample(
                        name='Success',
                        value={'detail': _('Password has been changed successfully.')},
                    )
                ]
            ),
            400: GenericOpenApiResponse400
        },
        examples=[
            OpenApiExample(
                name='Example',
                request_only=True,
                value={
                    'password': 'current_password',
                    'new_password1': 'new_password',
                    'new_password2': 'new_password',

                },
            ),
        ],
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data,
                                         context={'request': request})
        serializer.is_valid(raise_exception=True)

        user = request.user
        new_password = serializer.validated_data['new_password1']
        user.set_password(new_password)
        user.save()

        user_action_logger.info('Password changed.', extra={'user_id': user.id,
                                                            'client_ip': get_ip_from_request(request)})
        # Inform user via email
        task_change_password_mail(user_email=user.email)

        return Response(
            {'detail': _('Password has been changed successfully.')},
            status=status.HTTP_200_OK
        )


class PasswordResetRequestView(GenericAPIView):
    """
    A password reset code will send to provided email if email exists and is_active
    field on user is True.
    """
    permission_classes = [AllowAny]
    serializer_class = PasswordResetRequestSerializer

    @extend_schema(
        summary='Password reset request.',
        description='If email exists and is_active field is True Then send password reset code to user.',
        tags=['Account Password Management'],
        request=PasswordResetRequestSerializer,
        responses={
            200: OpenApiResponse(
                description='Password reset request successful.',
                response=GenericSuccessSerializer,
                examples=[
                    OpenApiExample(
                        name='Success',
                        value={'detail': _('Password reset code sent to your email(user_email_here).')},
                    )
                ]
            ),
            400: GenericOpenApiResponse400,
        },
        examples=[
            OpenApiExample(
                name='Example',
                request_only=True,
                value={
                    'email': 'user@example.com',
                },
            ),
        ],
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_email = serializer.validated_data['email']
        # Create PasswordResetCode object
        user = get_user_model().objects.get(email=user_email)
        prc = PasswordResetCode.objects.create(user=user)
        # Send password reset code to users email
        task_password_reset_request_mail(user_email=user_email,
                                         password_reset_code=prc.code)

        # Log user action
        user_action_logger.info(f'Password reset request ({user_email}).',
                                extra={'user_id': 'Anonymous',
                                       'client_ip': get_ip_from_request(request)})

        return Response(
            {'detail': _(f'Password reset code sent to your email({user_email}).')},
            status=status.HTTP_200_OK
        )


class PasswordResetView(GenericAPIView):
    """
    After PasswordResetRequestView provides code,
    user this view to set new passwords.
    """
    permission_classes = [AllowAny]
    serializer_class = PasswordResetSerializer

    @extend_schema(
        summary='Password reset.',
        description='Reset user password if provided code is valid and not expired.',
        tags=['Account Password Management'],
        request=PasswordResetSerializer,
        responses={
            200: OpenApiResponse(
                description='Password reset successful.',
                response=PasswordResetSerializer,
                examples=[
                    OpenApiExample(
                        name='Success',
                        value={'detail': _('Password reset for account(user_email_here) completed.')},
                    )
                ]
            ),
            400: GenericOpenApiResponse400,
        },
        examples=[
            OpenApiExample(
                name='Example',
                request_only=True,
                value={
                    'code': '123456',
                    'new_password1': 'new_password',
                    'new_password2': 'new_password',
                },
            ),
        ],
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        # Get Password request code object
        prc = PasswordResetCode.objects.get(code=serializer.validated_data['code'])
        user = prc.user
        user_email = user.email

        user.set_password(serializer.validated_data['new_password1'])
        user.save()
        user_action_logger.info(f'Password reset for account({user_email}) completed.',
                                extra={'user_id': 'Anonymous',
                                       'client_ip': get_ip_from_request(request)})

        # Delete PasswordResetCode object
        prc.delete()

        return Response(
            {'detail': _(f'Password reset for account({user_email}) completed.')},
            status=status.HTTP_200_OK)


class RegisterView(CreateAPIView):
    """Create a new user account."""
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

    @extend_schema(
        summary='Create a new user account.',
        description='Create a new user account.',
        tags=['Account'],
        request=RegisterSerializer,
        responses={
            201: OpenApiResponse(
                description='Account created successfully.',
                response=RegisterSerializer,
                examples=[
                    OpenApiExample(
                        name='Success',
                        value={
                            'id': 5,
                            'email': 'user@example.com',
                            'first_name': 'John',
                            'last_name': 'Doe',
                            'cellphone': '09123456789',
                        },
                    )
                ]
            ),
            400: GenericOpenApiResponse400,
        },
        examples=[
            OpenApiExample(
                name='Example',
                request_only=True,
                value={
                    'email': 'user@example.com',
                    'password': 'password',
                    'password_repeat': 'password',
                    'first_name': 'John',
                    'last_name': 'Doe',
                    'cellphone': '09123456789',
                },
            ),
        ],
    )
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        user_action_logger.info('User registered.',
                                extra={'user_id': response.data['id'],
                                       'client_ip': get_ip_from_request(request)})

        return response


ManageUserViewUpdateSchema = extend_schema(
    summary='Update authenticated user detail.',
    description='Update authenticated user detail.',
    tags=['Account Detail'],
    request=ManageUserSerializer,
    responses={
        200: OpenApiResponse(
            description='Account updated successfully.',
            response=ManageUserSerializer,
            examples=[
                OpenApiExample(
                    name='Success',
                    value={
                        'id': 5,
                        'email': 'user@example.com',
                        'first_name': 'John',
                        'last_name': 'Doe',
                        'cellphone': '09123456789',
                    },
                )
            ]
        ),
        400: GenericOpenApiResponse400,
        401: GenericOpenApiResponse401,

    },
    examples=[
        OpenApiExample(
            name='Example',
            request_only=True,
            value={
                "email": "user@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "cellphone": "09123456789",
            },
        ),

    ],
),


@extend_schema_view(
    get=extend_schema(
        summary='Retrieve authenticated user detail.',
        description='Retrieve authenticated user detail.',
        tags=['Account Detail'],
        request=ManageUserSerializer,
        responses={
            200: OpenApiResponse(
                response=ManageUserSerializer,
                examples=[
                    OpenApiExample(
                        name='A user detail.',
                        value={
                            'id': 5,
                            'email': 'user@example.com',
                            'first_name': 'John',
                            'last_name': 'Doe',
                            'cellphone': '09123456789',
                        },
                    )
                ]
            ),
            401: GenericOpenApiResponse401,
        },
    ),
    patch=ManageUserViewUpdateSchema,
    put=ManageUserViewUpdateSchema,

)
class ManageUserView(RetrieveUpdateAPIView):
    """Retrieve and update authenticated user data."""
    permission_classes = [IsAuthenticated]
    serializer_class = ManageUserSerializer

    def get_object(self):
        """Return authenticated user."""
        return self.request.user

    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        user_action_logger.info('User details retrieved.',
                                extra={'user_id': request.user.id,
                                       'client_ip': get_ip_from_request(request)})
        return response

    def put(self, request, *args, **kwargs):
        response = super().put(request, *args, **kwargs)
        user_action_logger.info('User details updated(PUT).',
                                extra={'user_id': request.user.id,
                                       'client_ip': get_ip_from_request(request)})
        return response

    def patch(self, request, *args, **kwargs):
        response = super().patch(request, *args, **kwargs)
        user_action_logger.info('User details updated(PATCH).',
                                extra={'user_id': request.user.id,
                                       'client_ip': get_ip_from_request(request)})
        return response
