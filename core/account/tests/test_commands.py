"""Test Custom management commands."""
from unittest.mock import patch
from psycopg2 import OperationalError as Psycopg2OpError

from django.test import TestCase
from django.db.utils import OperationalError

from django.core.management import call_command


@patch("account.management.commands.wait_for_db.time.sleep", return_value=None)
@patch("account.management.commands.wait_for_db.connections")
class TestWaitForDbCommand(TestCase):
    """Test wait_for_db management command."""

    def test_wait_for_db_immediately_available(self, mock_connections, mock_sleep) -> None:
        """Test database is immediately available."""
        mock_connection = mock_connections['default']
        mock_connection.cursor.return_value = True

        call_command('wait_for_db')

        mock_connection.cursor.assert_called_once()
        mock_sleep.assert_not_called()

    def test_wait_for_db_retry(self, mock_connections, mock_sleep):
        """Test database retry works."""
        mock_connection = mock_connections['default']

        mock_connection.cursor.side_effect = [Psycopg2OpError] * 3 + \
                                             [OperationalError] * 2 + \
                                             [True]
        call_command('wait_for_db')

        self.assertEqual(mock_connection.cursor.call_count, 6)
        self.assertEqual(mock_sleep.call_count, 5)
