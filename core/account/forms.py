"""Forms for account app."""
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm, UserChangeForm


class MyUserCreationForm(UserCreationForm):
    """My custom user creation form."""

    class Meta:
        model = get_user_model()
        fields = ('email',)


class MyUserChangeForm(UserChangeForm):
    """My custom user change form."""

    class Meta:
        model = get_user_model()
        fields = ('email',)
