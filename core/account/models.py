"""Models for account app."""
import random
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from account.validators import validate_cellphone_length_startswith
from account.managers import UserManager


class User(AbstractBaseUser, PermissionsMixin):
    """My custom user model which supports using email instead of username."""
    email = models.EmailField(_('email address'), unique=True)
    first_name = models.CharField(_("first name"), max_length=150, blank=True)
    last_name = models.CharField(_("last name"), max_length=150, blank=True)
    cellphone = models.CharField(_("cellphone"), max_length=11, unique=True,
                                 blank=True, validators=[validate_cellphone_length_startswith])
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    @property
    def full_name(self) -> str:
        """Returns user full name."""
        return f'{self.first_name} {self.last_name}'

    def __str__(self):
        return self.email

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')


def generate_random_code() -> str:
    """Returns string of random number."""
    from string import digits
    return ''.join(random.choice(digits) for _ in range(settings.PASSWORD_RESET_CODE_LENGTH))


class PasswordResetCode(models.Model):
    """Password reset code that keeps codes and expire_datetime for requested user."""
    user = models.OneToOneField(to=get_user_model(), on_delete=models.CASCADE,
                                related_name='password_reset_code', verbose_name=_('user'))
    code = models.CharField(max_length=settings.PASSWORD_RESET_CODE_LENGTH,
                            default=generate_random_code,
                            verbose_name=_('code'))
    created = models.DateTimeField(auto_now_add=True, verbose_name=_('created'))
    expires_at = models.DateTimeField(verbose_name=_('expires at'))

    def save(self, *args, **kwargs):
        """Delete user previous codes and set expires at."""
        if self.id is None:
            # New object
            # Delete any PasswordRestCode that user has
            PasswordResetCode.objects.filter(user=self.user).delete()
            # set expire datetime
            self.expires_at = timezone.now() + timedelta(
                minutes=settings.PASSWORD_RESET_CODE_EXPIRE_MINUTES
            )

        super().save(*args, **kwargs)

    def is_expired(self) -> bool:
        """Returns True if code is expired."""
        return timezone.now() > self.expires_at

    def __str__(self):
        return self.code

    class Meta:
        verbose_name = _('password reset code')
        verbose_name_plural = _('password reset codes')
