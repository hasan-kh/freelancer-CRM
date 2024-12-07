"""Tests for the account app views."""
from datetime import datetime
from unittest.mock import patch

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from rest_framework import status
from rest_framework.test import APIClient

from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from utils.error_handling import (
    assert_expected_error_in_response_data, assert_expected_error_code_in_response_data,
    MyErrors
)
from account.models import PasswordResetCode, generate_random_code
from account.serializers import RegisterSerializer, ManageUserSerializer


USER_LOGIN_URL = reverse('account:token_obtain_pair')
USER_CHANGE_PASSWORD_URL = reverse('account:change-password')
USER_RESET_PASSWORD_REQ_URL = reverse('account:password-reset-request')
USER_RESET_PASSWORD_URL = reverse('account:password-reset')
USER_REGISTER_URL = reverse('account:register')
USER_MANAGE_URL = reverse('account:manage')


def create_user(email='user@example.com', password='password123', **params):
    return get_user_model().objects.create_user(email=email, password=password, **params)


def create_user_complete_fields():
    params = {
        'first_name': 'john',
        'last_name': 'doe',
        'cellphone': '09000000000',
    }
    return get_user_model().objects.create_user(**params)


class PublicAccountViewsTests(TestCase):
    """Test the public unauthenticated features of the account views api."""

    def setUp(self) -> None:
        self.client = APIClient()

    def test_login_success(self) -> None:
        """Test user can log in successfully."""
        payload = {'email': 'user@example.com', 'password': 'password123'}
        user = create_user(email=payload['email'], password=payload['password'])

        with self.assertLogs('user_action', 'INFO') as log:
            res = self.client.post(USER_LOGIN_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_200_OK)

        access_token = res.data.get('access')
        refresh_token = res.data.get('refresh')
        access_expires_at = res.data.get('access_expires_at')
        refresh_expires_at = res.data.get('refresh_expires_at')

        # Assert response is complete
        self.assertIsNotNone(access_token)
        self.assertIsNotNone(refresh_token)
        self.assertIsNotNone(access_expires_at)
        self.assertIsNotNone(refresh_expires_at)

        # Verify access token

        # Set verify attribute to False on Token classes because the class is strictly validating the token
        # and decoding it when it's instantiated so even if token is valid in current time, it will raise exceptions.
        access_token_object = AccessToken(access_token, verify=False)

        self.assertEqual(access_token_object['user_id'], user.id)  # token belongs to user
        self.assertTrue(access_token_object['exp'] > datetime.utcnow().timestamp())  # it's not expired

        # Verify refresh token

        refresh_token_object = RefreshToken(refresh_token, verify=False)
        self.assertEqual(refresh_token_object['user_id'], user.id)  # token belongs to user
        self.assertTrue(refresh_token_object['exp'] > datetime.utcnow().timestamp())  # it's not expired

        # Assert log
        log_record = log.records[0]
        self.assertEqual(log_record.user_id, user.id)
        self.assertEqual(log_record.message, 'User logged in.')

    def test_login_with_not_existing_email_fails(self) -> None:
        """Test login with not existing email fails."""
        payload = {'email': 'notexisting@example.com', 'password': 'password123'}

        with self.assertLogs('user_action', 'WARNING') as log:
            res = self.client.post(USER_LOGIN_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        assert_expected_error_in_response_data(
            test_case_object=self,
            response_data=res.data,
            field_name='email',
            expected_error=MyErrors.USER_EMAIL_NOT_FOUND,
            expected_error_context={'email': payload['email']}
        )

        # Assert log
        self.assertEqual(log.records[0].message, f'Login failed, email({payload["email"]}) not found.')

    def test_login_with_inactive_account_fails(self) -> None:
        """Test login with inactive account fails."""
        payload = {'email': 'inactive@example.com', 'password': 'password123'}
        create_user(payload['email'], payload['password'], is_active=False)

        with self.assertLogs('user_action', 'WARNING') as log:
            res = self.client.post(USER_LOGIN_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        assert_expected_error_in_response_data(
            test_case_object=self,
            response_data=res.data,
            field_name='email',
            expected_error=MyErrors.USER_INACTIVE,
            expected_error_context={'email': payload['email']}
        )

        # Assert log
        log_record = log.records[0]
        self.assertEqual(log_record.user_id, log_record.user_id)
        self.assertEqual(log_record.message, f'Login failed, user({payload["email"]}) is inactive.')

    def test_login_with_wrong_credentials_fails(self) -> None:
        """Test login with wrong credentials fails."""
        payload = {'email': 'sample@example.com', 'password': 'wrong_password'}
        create_user(payload['email'], 'password123')

        with self.assertLogs('user_action', 'WARNING') as log:
            res = self.client.post(USER_LOGIN_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        assert_expected_error_in_response_data(
            test_case_object=self,
            response_data=res.data,
            field_name='non_field_errors',
            expected_error=MyErrors.INCORRECT_CREDENTIALS,
        )

        # Assert log
        self.assertEqual(log.records[0].message, f'Login failed, incorrect credentials({payload["email"]}).')

    def test_login_with_blank_fields_fails(self) -> None:
        """Test login with blank field/fields fails."""
        samples = [
            # ['email', 'password', 'error_field_name'],
            ['user@example.com', '', 'password'],
            ['', 'password123', 'email'],
        ]

        for sample in samples:
            with self.subTest(sample=sample):
                payload = {
                    'email': sample[0],
                    'password': sample[1]
                }
                res = self.client.post(USER_LOGIN_URL, payload)

                self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
                assert_expected_error_code_in_response_data(
                    test_case_object=self,
                    response_data=res.data,
                    field_name=sample[2],
                    expected_error_code=MyErrors.BLANK['code'],
                )

        # Test both fields blank
        payload = {'email': '', 'password': ''}
        res = self.client.post(USER_LOGIN_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

        assert_expected_error_code_in_response_data(
            test_case_object=self,
            response_data=res.data,
            field_name='email',
            expected_error_code=MyErrors.BLANK['code'],
        )
        assert_expected_error_code_in_response_data(
            test_case_object=self,
            response_data=res.data,
            field_name='password',
            expected_error_code=MyErrors.BLANK['code'],
        )

    def test_change_password_anon_user_fails(self) -> None:
        """Test that anonymous user can not change the password."""
        res = self.client.post(USER_CHANGE_PASSWORD_URL, {})

        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('account.views.task_password_reset_request_mail', return_value=None)
    def test_reset_password_request_succeeds(self, mocked_send_mail) -> None:
        """Test reset password request succeeds."""
        user = create_user()
        payload = {'email': user.email}
        with self.assertLogs('user_action', 'INFO') as log:
            res = self.client.post(USER_RESET_PASSWORD_REQ_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['detail'],
                         _(f'Password reset code sent to your email({payload["email"]}).'))
        self.assertEqual(PasswordResetCode.objects.filter(user=user).count(), 1)
        prc = user.password_reset_code
        self.assertFalse(prc.is_expired())
        mocked_send_mail.assert_called_once_with(user_email=user.email,
                                                 password_reset_code=prc.code)

        # Assert log
        self.assertEqual(f'Password reset request ({user.email}).', log.records[0].message)

    @patch('account.views.task_password_reset_request_mail', return_value=None)
    def test_password_reset_request_not_existing_email_fails(self, mocked_send_mail) -> None:
        """Test password reset request not existing email fails."""
        payload = {'email': 'not_existing@example.com'}

        with self.assertLogs('user_action', 'WARNING') as log:
            res = self.client.post(USER_RESET_PASSWORD_REQ_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        assert_expected_error_in_response_data(test_case_object=self,
                                               response_data=res.data,
                                               field_name='email',
                                               expected_error=MyErrors.USER_EMAIL_NOT_FOUND,
                                               expected_error_context={'email': payload['email']})
        # Assert mail did not send
        mocked_send_mail.assert_not_called()

        # Assert log
        self.assertEqual(f'Password reset fails, account with email({payload["email"]}) not found.',
                         log.records[0].message)

    @patch('account.views.task_password_reset_request_mail', return_value=None)
    def test_password_reset_request_not_active_account_fails(self, mocked_send_mail) -> None:
        """Test password reset request for not active account fails."""
        user = create_user(is_active=False)
        payload = {
            'email': user.email
        }
        with self.assertLogs('user_action', 'WARNING') as log:
            res = self.client.post(USER_RESET_PASSWORD_REQ_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        assert_expected_error_in_response_data(test_case_object=self,
                                               response_data=res.data,
                                               field_name='email',
                                               expected_error=MyErrors.USER_INACTIVE,
                                               expected_error_context={'email': payload['email']})

        # Assert mail did not send
        mocked_send_mail.assert_not_called()

        # Assert log
        self.assertEqual(f'Password reset fails, account with email({payload["email"]}) is inactive.',
                         log.records[0].message)

    def test_password_reset_succeeds(self) -> None:
        """Test password reset succeeds."""
        user = create_user()
        code = PasswordResetCode.objects.create(user=user).code
        payload = {
            'code': code,
            'new_password1': 'password456',
            'new_password2': 'password456',
        }

        with self.assertLogs('user_action', 'INFO') as log:
            res = self.client.post(USER_RESET_PASSWORD_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_200_OK)

        self.assertEqual(res.data['detail'],
                         _(f'Password reset for account({user.email}) completed.'))

        # Check PasswordResetCode object deleted
        self.assertFalse(PasswordResetCode.objects.filter(user=user, code=code).exists())

        # Assert log
        self.assertEqual(f'Password reset for account({user.email}) completed.', log.records[0].message)

    def test_password_reset_invalid_code_fails(self) -> None:
        """Test user password reset attempt with invalid code fails."""
        payload = {
            'code': generate_random_code(),
            'new_password1': 'new_password',
            'new_password2': 'new_password',
        }

        with self.assertLogs('user_action', 'WARNING') as log:
            res = self.client.post(USER_RESET_PASSWORD_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

        assert_expected_error_in_response_data(test_case_object=self,
                                               response_data=res.data,
                                               field_name='code',
                                               expected_error=MyErrors.CODE_INVALID)

        # Assert log
        self.assertEqual('Password reset fails, code does not exist.', log.records[0].message)

    @patch('account.models.PasswordResetCode.is_expired', return_value=True)
    def test_password_reset_expired_code_fails(self, mocked_is_expired) -> None:
        """Test user password reset attempt with expired code fails."""

        code = PasswordResetCode.objects.create(user=create_user()).code
        payload = {
            'code': code,
            'new_password1': 'new_password',
            'new_password2': 'new_password',
        }

        with self.assertLogs('user_action', 'WARNING') as log:
            res = self.client.post(USER_RESET_PASSWORD_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        assert_expected_error_in_response_data(test_case_object=self,
                                               response_data=res.data,
                                               field_name='code',
                                               expected_error=MyErrors.CODE_EXPIRED)

        # Assert is_expired method on PasswordResetCode object called once
        mocked_is_expired.assert_called_once()

        # Assert log
        self.assertEqual(f'Password reset fails, code({code}) is expired.', log.records[0].message)

    def test_password_reset_with_short_new_password_fails(self) -> None:
        """Test user resets password with short new password fails."""
        user_password = 'password123'
        user = create_user(password=user_password)
        code = PasswordResetCode.objects.create(user=user).code
        sample_new_passwords = [
            ['short', 'short'],  # short password, min length is 8
            ['1234567', '1234567'],  # length is 7
        ]

        for new_pass1, new_pass2 in sample_new_passwords:
            with self.subTest(new_pass1=new_pass1, new_pass2=new_pass2):
                payload = {
                    'code': code,
                    'new_password1': new_pass1,
                    'new_password2': new_pass2,
                }
                res = self.client.post(USER_RESET_PASSWORD_URL, payload)

                self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
                assert_expected_error_in_response_data(test_case_object=self,
                                                       response_data=res.data,
                                                       field_name='new_password1',
                                                       expected_error=MyErrors.PASSWORD_TOO_SHORT)

        # Check current password stays the same
        user.refresh_from_db()
        self.assertTrue(user.check_password(user_password))

    def test_password_reset_mismatch_newpasswords_fails(self) -> None:
        """Test user reset password with mismatch new passwords fails."""
        user_password = 'password123'
        user = create_user(password=user_password)
        code = PasswordResetCode.objects.create(user=user).code
        payload = {
            'code': code,
            'new_password1': '12345678',
            'new_password2': '123456789',
        }

        with self.assertLogs('user_action', 'WARNING') as log:
            res = self.client.post(USER_RESET_PASSWORD_URL, payload)

        self.assertIn('Password reset fails, new passwords do not match.', log.output[0])

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        assert_expected_error_in_response_data(test_case_object=self,
                                               response_data=res.data,
                                               field_name='non_field_errors',
                                               expected_error=MyErrors.PASSWORDS_DO_NOT_MATCH)

        # Check current password stays the same
        user.refresh_from_db()
        self.assertTrue(user.check_password(user_password))

        # Assert log
        self.assertEqual('Password reset fails, new passwords do not match.', log.records[0].message)

    def test_password_reset_not_passing_required_fields_fails(self) -> None:
        """Test user reset password but not passing required fields fails."""
        user_password = 'password123'
        user = create_user(password=user_password)
        code = PasswordResetCode.objects.create(user=user)
        sample_payloads = [
            ['', '12345678', '12345678', 'code'],
            [code, '', '12345678', 'new_password1'],
            [code, '12345678', '', 'new_password2'],
        ]

        for payload in sample_payloads:
            with self.subTest(payload=payload):
                payload_dict = {
                    'code': payload[0],
                    'new_password1': payload[1],
                    'new_password2': payload[2],
                }
                res = self.client.post(USER_RESET_PASSWORD_URL, payload_dict)

                self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
                assert_expected_error_code_in_response_data(
                    test_case_object=self,
                    response_data=res.data,
                    field_name=payload[3],
                    expected_error_code=MyErrors.BLANK['code'],
                )

        # Check current password stays the same
        user.refresh_from_db()
        self.assertTrue(user.check_password(user_password))

    def test_user_register_success(self):
        """Test user registers successfully."""
        payload = {
            'email': 'user@example.com',
            'password': 'password123',
            'password_repeat': 'password123',
            'first_name': 'John',
            'last_name': 'Doe',
            'cellphone': '09000000000',
        }
        with self.assertLogs('user_action', 'INFO') as log:
            res = self.client.post(USER_REGISTER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_201_CREATED)

        # Get user from database and check data with related serializer
        user = get_user_model().objects.get(email=payload['email'])

        serializer = RegisterSerializer(instance=user)
        self.assertDictEqual(serializer.data, res.data)

        # Check password
        self.assertTrue(user.check_password(payload['password']))

        # Check full name
        self.assertEqual(user.full_name,
                         f'{payload["first_name"]} {payload["last_name"]}')

        # Check cellphone
        self.assertEqual(user.cellphone, payload['cellphone'])

        # Assert log
        log_record = log.records[0]
        self.assertEqual(user.id, log_record.user_id)
        self.assertEqual('User registered.', log_record.message)

    def test_user_register_existing_email_fails(self) -> None:
        """Test user register with existing email fails."""
        existing_email = 'user@example.com'
        create_user(email=existing_email)
        payload = {
            'email': existing_email,
            'password': 'password123',
            'password_repeat': 'password123',
            'first_name': 'John',
            'last_name': 'Doe',
            'cellphone': '09000000000',
        }
        res = self.client.post(USER_REGISTER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        assert_expected_error_code_in_response_data(
            test_case_object=self,
            response_data=res.data,
            field_name='email',
            expected_error_code='unique',
        )

    def test_user_register_short_password_fails(self) -> None:
        """Test register user with short password fails."""
        payload = {
            'email': 'user@example.com',
            'password': '1234567',
            'password_repeat': '1234567',
            'first_name': 'John',
            'last_name': 'Doe',
            'cellphone': '09000000000',
        }
        res = self.client.post(USER_REGISTER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        assert_expected_error_in_response_data(test_case_object=self,
                                               response_data=res.data,
                                               field_name='password',
                                               expected_error=MyErrors.PASSWORD_TOO_SHORT)

    def test_user_register_with_missmatch_passwords_fails(self) -> None:
        """Test register user with missmatch passwords fails."""
        payload = {
            'email': 'user@example.com',
            'password': '12345678',
            'password_repeat': '12345679',
            'first_name': 'John',
            'last_name': 'Doe',
            'cellphone': '09000000000',
        }
        with self.assertLogs('user_action', 'WARNING') as log:
            res = self.client.post(USER_REGISTER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        assert_expected_error_in_response_data(test_case_object=self,
                                               response_data=res.data,
                                               field_name='non_field_errors',
                                               expected_error=MyErrors.PASSWORDS_DO_NOT_MATCH)

        # Assert log
        self.assertEqual('User register fails, passwords do not match.', log.records[0].message)

    def test_user_register_invalid_cellphone_fails(self) -> None:
        """Test that registration fails with invalid cellphone number."""
        payload = {
            'email': 'user@example.com',
            'password': '12345678',
            'password_repeat': '12345678',
            'first_name': 'John',
            'last_name': 'Doe',
            'cellphone': '',
        }
        invalid_cellphones = [
            '02100000000',  # don't start with 09
            'call-0912',  # it's not numeric
            '0900000000'  # it's not 11 digits
        ]
        for cellphone in invalid_cellphones:
            with self.subTest(cellphone=cellphone):
                payload['cellphone'] = cellphone
                res = self.client.post(USER_REGISTER_URL, payload)

                self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
                assert_expected_error_in_response_data(test_case_object=self,
                                                       response_data=res.data,
                                                       field_name='cellphone',
                                                       expected_error=MyErrors.INVALID_CELLPHONE)


class PrivateAccountViewsTests(TestCase):
    """Test the private authenticated features of the account views api."""

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

    @patch('account.views.task_change_password_mail', return_value=1)
    def test_user_change_password_successfully(self, mocked_send_mail) -> None:
        """Test user changes password successfully."""
        payload = {
            'password': self.user_password,
            'new_password1': 'new_password',
            'new_password2': 'new_password',
        }
        with self.assertLogs('user_action', level='INFO') as log:
            res = self.client.post(USER_CHANGE_PASSWORD_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['detail'], _('Password has been changed successfully.'))
        # Check new password set correctly
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(payload['new_password1']))

        # Check task_change_password_mail method called once
        mocked_send_mail.assert_called_once_with(user_email=self.user.email)

        # Assert log
        log_records = log.records[0]
        self.assertEqual('password changed.', log_records.message.lower())
        self.assertEqual(self.user.id, log_records.user_id)

    def test_user_change_password_invalid_current_password_fails(self) -> None:
        """Test user changes password with invalid current password fails."""
        payload = {
            'password': 'wrong_password',
            'new_password1': 'new_password',
            'new_password2': 'new_password',
        }

        with self.assertLogs('user_action', 'WARNING') as log:
            res = self.client.post(USER_CHANGE_PASSWORD_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        assert_expected_error_in_response_data(test_case_object=self,
                                               response_data=res.data,
                                               field_name='password',
                                               expected_error=MyErrors.PASSWORD_INCORRECT)
        # Check current password stays the same
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.user_password))

        # Assert log
        log_records = log.records[0]
        self.assertEqual(self.user.id, log_records.user_id)
        self.assertEqual('Change password fails, incorrect current password.', log_records.message)

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

                self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
                assert_expected_error_in_response_data(test_case_object=self,
                                                       response_data=res.data,
                                                       field_name='new_password1',
                                                       expected_error=MyErrors.PASSWORD_TOO_SHORT)

        # Check current password stays the same
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.user_password))

    def test_user_change_password_mismatch_fails(self) -> None:
        """Test user changes password with mismatch new passwords fails."""
        payload = {
            'password': self.user_password,
            'new_password1': '12345678',
            'new_password2': '123456789',
        }

        with self.assertLogs('user_action', 'WARNING') as log:
            res = self.client.post(USER_CHANGE_PASSWORD_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        assert_expected_error_in_response_data(test_case_object=self,
                                               response_data=res.data,
                                               field_name='non_field_errors',
                                               expected_error=MyErrors.PASSWORDS_DO_NOT_MATCH)

        # Check current password stays the same
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.user_password))

        # Assert log
        log_records = log.records[0]
        self.assertEqual(self.user.id, log_records.user_id)
        self.assertEqual('Change password fails, new passwords do not match.', log_records.message)

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

                self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
                assert_expected_error_code_in_response_data(
                    test_case_object=self,
                    response_data=res.data,
                    field_name=payload[3],
                    expected_error_code=MyErrors.BLANK['code'],
                )

        # Check current password stays the same
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.user_password))

    def test_manage_user_retrieve_data_success(self) -> None:
        """Test retrieving user data."""
        user = create_user(email='john@example.com', first_name='John', last_name='Doe',
                           cellphone='09000000000')
        self.client.force_authenticate(user)

        with self.assertLogs('user_action', 'INFO') as log:
            res = self.client.get(USER_MANAGE_URL)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        serializer = ManageUserSerializer(instance=user)
        self.assertEqual(res.data, serializer.data)

        # Assert log
        log_record = log.records[0]
        self.assertEqual(user.id, log_record.user_id)
        self.assertEqual('User details retrieved.', log_record.message)

    def test_manage_user_update_success(self) -> None:
        """Test updating user data (PUT) successfully."""
        payload = {
            'email': self.user.email,
            'first_name': 'John',
            'last_name': 'Doe',
            'cellphone': '09000000000',

        }
        with self.assertLogs('user_action', 'INFO') as log:
            res = self.client.put(USER_MANAGE_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        serializer = ManageUserSerializer(instance=self.user)
        self.assertEqual(res.data, serializer.data)

        # Assert log
        log_record = log.records[0]
        self.assertEqual(self.user.id, log_record.user_id)
        self.assertEqual('User details updated(PUT).', log_record.message)

    def test_manage_user_partial_update_success(self) -> None:
        """Test partial updating user data (PATCH) successfully."""
        payload = {
            'email': self.user.email,
            'cellphone': '09000000000',

        }
        with self.assertLogs('user_action', 'INFO') as log:
            res = self.client.patch(USER_MANAGE_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        serializer = ManageUserSerializer(instance=self.user)
        self.assertEqual(res.data, serializer.data)

        # Assert log
        log_record = log.records[0]
        self.assertEqual(self.user.id, log_record.user_id)
        self.assertEqual('User details updated(PATCH).', log_record.message)

    def test_manage_user_update_existing_email_cellphone(self) -> None:
        """Test updating user data (PUT) with existing email and cellphone fails."""
        existing_email = 'exist@example.com'
        existing_cellphone = '09000000001'
        create_user(email=existing_email, password='password123', cellphone=existing_cellphone)
        payload = {
            'email': existing_email,
            'first_name': 'John',
            'last_name': 'Doe',
            'cellphone': existing_cellphone,
        }
        res = self.client.put(USER_MANAGE_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

        assert_expected_error_code_in_response_data(
            test_case_object=self,
            response_data=res.data,
            field_name='email',
            expected_error_code='unique',
        )

        assert_expected_error_code_in_response_data(
            test_case_object=self,
            response_data=res.data,
            field_name='email',
            expected_error_code='unique',
        )

        self.user.refresh_from_db()

        # Make sure email and cellphone didn't change
        self.assertNotEqual(self.user.email, existing_email)
        self.assertNotEqual(self.user.cellphone, existing_cellphone)

    def test_manage_user_partial_update_existing_email_cellphone(self) -> None:
        """Test partial updating user data (PATCH) with existing email and cellphone fails."""
        existing_email = 'exist@example.com'
        existing_cellphone = '09000000001'
        create_user(email=existing_email, password='password123', cellphone=existing_cellphone)
        payload = {
            'email': existing_email,
            'cellphone': existing_cellphone,
        }
        res = self.client.patch(USER_MANAGE_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

        assert_expected_error_code_in_response_data(
            test_case_object=self,
            response_data=res.data,
            field_name='email',
            expected_error_code='unique',
        )

        assert_expected_error_code_in_response_data(
            test_case_object=self,
            response_data=res.data,
            field_name='cellphone',
            expected_error_code='unique',
        )

        self.user.refresh_from_db()

        # Make sure email and cellphone didn't change
        self.assertNotEqual(self.user.email, existing_email)
        self.assertNotEqual(self.user.cellphone, existing_cellphone)
