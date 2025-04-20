"""App module for account."""
from django.apps import AppConfig


class AccountConfig(AppConfig):
    """App config for account."""
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'account'

    def ready(self) -> None:
        """Account app setups."""

        # Load signals
        from account import signals  # noqa: F401  # pylint: disable=import-outside-toplevel, unused-import
