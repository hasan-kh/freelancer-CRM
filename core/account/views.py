"""Views for accounts app."""
from django.utils.translation import gettext_lazy as _

from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from account.serializers import (
    UserChangePasswordSerializer
)


class ChangePasswordView(GenericAPIView):
    """Update user password after confirm current password."""
    permission_classes = [IsAuthenticated]
    serializer_class = UserChangePasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data,
                                         context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            'detail': _('Password has been changed successfully.')},
            status=status.HTTP_200_OK
        )
