"""Tests for the account app views."""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from utils.error_handling import ErrorCodes, ValidationDetails


USER_CHANGE_PASSWORD_URL = reverse('account:change-password')


class PublicAccountViewsTests(TestCase):
    """Test the public features of the account views api."""
    pass


class PrivateAccountViewsTests(TestCase):
    """Test the private features of the account views api."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.user_password = 'password123'
        cls.user = get_user_model().objects.create_user(
            email='user@example.com',
            password='password123',
        )

    def setUp(self) -> None:
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_user_change_password_successfully(self) -> None:
        """Test user changes password successfully."""
        payload = {
            'password': self.user_password,
            'new_password1': 'new_password',
            'new_password2': 'new_password',
        }
        with self.assertLogs('django', level='INFO') as log:
            res = self.client.post(USER_CHANGE_PASSWORD_URL, payload)

            self.assertEqual(res.status_code, status.HTTP_200_OK)
            expected_log = f'User (ID: {self.user.id}) changed password.'
            self.assertIn(expected_log, log.output[0])

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(payload['new_password1']))

    def test_user_change_password_invalid_current_password_fails(self) -> None:
        """Test user changes password with invalid current password fails."""
        payload = {
            'password': 'wrong_password',
            'new_password1': 'new_password',
            'new_password2': 'new_password',
        }

        res = self.client.post(USER_CHANGE_PASSWORD_URL, payload)
        errors = res.data['errors']

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(errors['password']['code'], ErrorCodes.PASSWORD_INCORRECT)
        self.assertEqual(errors['password']['detail'], ValidationDetails.PASSWORD_INCORRECT)

        self.user.refresh_from_db()
        # Check current password stays the same
        self.assertTrue(self.user.check_password(self.user_password))

    def test_user_change_password_with_short_new_password_fails(self) -> None:
        """Test user changes password with short new password fails."""
        sample_new_passwords = [
            ['short', 'short'],  # short password, min length is 8
            ['1234567', '1234567'],  # length is 7
        ]

        for new_pass1, new_pass2 in sample_new_passwords:
            with self.subTest(new_pass1=new_pass1, new_pass2=new_pass2):
                payload = {
                    'password': self.user_password,
                    'new_password1': new_pass1,
                    'new_password2': new_pass2,
                }
                res = self.client.post(USER_CHANGE_PASSWORD_URL, payload)
                errors = res.data['errors']

                self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertEqual(errors['new_password1']['code'],
                                 ErrorCodes.PASSWORD_TOO_SHORT)
                self.assertEqual(errors['new_password1']['detail'],
                                 ValidationDetails.PASSWORD_TOO_SHORT)

        self.user.refresh_from_db()
        # Check current password stays the same
        self.assertTrue(self.user.check_password(self.user_password))

    def test_user_change_password_mismatch_fails(self) -> None:
        """Test user changes password with mismatch new passwords fails."""
        payload = {
            'password': self.user_password,
            'new_password1': '12345678',
            'new_password2': '123456789',
        }

        res = self.client.post(USER_CHANGE_PASSWORD_URL, payload)

        errors = res.data['errors']

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(errors['non_field_errors']['code'],
                         ErrorCodes.PASSWORDS_DO_NOT_MATCH)
        self.assertEqual(errors['non_field_errors']['detail'],
                         ValidationDetails.PASSWORDS_DO_NOT_MATCH)

        self.user.refresh_from_db()
        # Check current password stays the same
        self.assertTrue(self.user.check_password(self.user_password))

    def test_user_change_not_passing_required_fields_fails(self) -> None:
        """Test user changes password but not passing required fields fails."""
        sample_payloads = [
            # [password, new_password1, new_password2, field]
            ['', '12345678', '12345678', 'password'],
            [self.user_password, '', '12345678', 'new_password1'],
            [self.user_password, '12345678', '', 'new_password2'],
        ]

        for payload in sample_payloads:
            with self.subTest(payload=payload):
                payload_dict = {
                    'password': payload[0],
                    'new_password1': payload[1],
                    'new_password2': payload[2],
                }
                res = self.client.post(USER_CHANGE_PASSWORD_URL, payload_dict)
                errors = res.data['errors']

                self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertEqual(errors[payload[3]]['code'],
                                 ErrorCodes.BLANK)

        self.user.refresh_from_db()
        # Check current password stays the same
        self.assertTrue(self.user.check_password(self.user_password))
