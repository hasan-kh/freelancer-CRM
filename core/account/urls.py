"""URLs for accounts app."""
from django.urls import path

from account.views import (
    CustomTokenObtainPairView, CustomTokenRefreshView, CustomTokenBlacklistView,
    ChangePasswordView, PasswordResetRequestView, PasswordResetView,
    RegisterUserView, ManageUserView,
)

app_name = 'account'
urlpatterns = [
    # path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token-refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', CustomTokenBlacklistView.as_view(), name='token_blacklist'),

    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('reset-password-request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('reset-password/', PasswordResetView.as_view(), name='password-reset'),

    path('register/', RegisterUserView.as_view(), name='register'),
    path('me/', ManageUserView.as_view(), name='manage'),

]
