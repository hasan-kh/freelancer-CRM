"""Admin for account app."""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as Auth_UserAdmin
from django.utils.translation import gettext_lazy as _
from account.forms import MyUserCreationForm, MyUserChangeForm
from account.models import User


@admin.register(User)
class UserAdmin(Auth_UserAdmin):
    """Admin class for User model."""
    add_form = MyUserCreationForm
    form = MyUserChangeForm
    model = User
    list_display = ('email', 'first_name', 'last_name', 'is_staff', 'is_active')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('first_name', 'last_name', 'email')
    readonly_fields = ('last_login', 'date_joined')
    ordering = ('-id',)
    filter_horizontal = (
        'groups',
        'user_permissions',
    )

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name')}),
        (
            _('Permissions'),
            {
                'fields': (
                    'is_active',
                    'is_staff',
                    'is_superuser',
                    'groups',
                    'user_permissions',
                ),
            },
        ),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": (
                "email", "password1", "password2", "is_active",
                "is_staff", "groups", "user_permissions"
            )}
         ),
    )
