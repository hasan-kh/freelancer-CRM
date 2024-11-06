"""URLs for accounts app."""
from django.urls import path

from account.views import ChangePasswordView

app_name = 'account'
urlpatterns = [
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
]
