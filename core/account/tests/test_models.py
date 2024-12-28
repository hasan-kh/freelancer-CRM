"""Test models for the accounts app."""
from unittest.mock import patch
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError
from django.conf import settings
from django.test import TestCase

from account.models import PasswordResetCode


class UserModelTests(TestCase):
    """Test user model."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.user_model = get_user_model()

    def test_create_user_success(self) -> None:
        """Test creating user is successful."""
        payload = {
            'email': 'test@example.com',
            'password': 'password123',
        }
        user = self.user_model.objects.create_user(**payload)

        self.assertEqual(user.email, payload['email'])
        self.assertTrue(user.check_password(payload['password']))
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

        # Check default fields
        self.assertEqual(user.first_name, '')
        self.assertEqual(user.last_name, '')
        self.assertEqual(user.cellphone, '')
        self.assertEqual(user.full_name.strip(), '')

    def test_create_user_define_default_fields(self) -> None:
        """Test creating user with defining of default."""
        payload = {
            'email': 'test@example.com',
            'password': 'password123',
            'first_name': 'john',
            'last_name': 'doe',
            'cellphone': '090000000',
        }
        user = self.user_model.objects.create_user(**payload)

        self.assertEqual(user.email, payload['email'])
        self.assertTrue(user.check_password(payload['password']))
        self.assertEqual(user.first_name, payload['first_name'])
        self.assertEqual(user.last_name, payload['last_name'])
        self.assertEqual(user.cellphone, payload['cellphone'])
        self.assertEqual(user.full_name, f'{payload["first_name"]} {payload["last_name"]}')

    def test_email_normalize_user_creation(self) -> None:
        """Test email is normalized for new users."""
        sample_emails = [
            ['test1@EXAMPLE.com', 'test1@example.com'],
            ['Test2@Example.com', 'Test2@example.com'],
            ['TEST3@EXAMPLE.COM', 'TEST3@example.com'],
            ['test4@example.COM', 'test4@example.com'],
        ]

        for email, expected in sample_emails:
            with self.subTest(email=email):
                user = self.user_model.objects.create_user(email=email, password='password123')
                self.assertEqual(user.email, expected)
                user.delete()

    def test_create_user_with_faulty_fields_raises_error(self) -> None:
        """Test creating user with faulty(empty/not defined) fields raises error."""
        with self.assertRaises(TypeError):
            self.user_model.objects.create_user()
        with self.assertRaises(TypeError):
            self.user_model.objects.create_user(email='')
        with self.assertRaises(ValueError):
            self.user_model.objects.create_user(email='', password='password123')

        user = self.user_model.objects.create_user(email='test@example.com', password='test123')
        self.assertFalse(hasattr(user, 'username'))

    def test_create_superuser(self) -> None:
        """Test creating a superuser is successful."""
        payload = {
            'email': 'test@example.com',
            'password': 'test123'
        }
        superuser = self.user_model.objects.create_superuser(**payload)

        self.assertEqual(superuser.email, payload['email'])
        self.assertTrue(superuser.check_password(payload['password']))
        self.assertTrue(superuser.is_active)
        self.assertTrue(superuser.is_staff)
        self.assertTrue(superuser.is_superuser)

    def test_create_superuser_with_faulty_fields_raises_error(self) -> None:
        """Test creating superuser with faulty(empty/not defined) fields raises error."""
        with self.assertRaises(TypeError):
            self.user_model.objects.create_superuser()
        with self.assertRaises(TypeError):
            self.user_model.objects.create_superuser(email='')
        with self.assertRaises(ValueError):
            self.user_model.objects.create_superuser(email='', password='password123')

        user = self.user_model.objects.create_superuser(
            email='test@example.com',
            password='test123'
        )
        self.assertFalse(hasattr(user, 'username'))

    def test_wrong_cellphone_raises_error(self) -> None:
        """Test create user with wrong cellphone raises ValueError."""
        user = self.user_model.objects.create_user(email='test@example.com',
                                                   password='password123')
        wrong_cellphones = [
            '090000000000',  # too long
            '0900000000',  # too short
            '01000000000',  # not starting with 09
        ]
        for cell in wrong_cellphones:
            with self.subTest(cell=cell):
                with self.assertRaises(ValidationError):
                    user.cellphone = cell
                    user.full_clean()

    def test_create_user_with_existing_email_fails(self) -> None:
        """Test creating user with existing email fails."""
        existing_email = 'exist@example.com'
        self.user_model.objects.create_user(email=existing_email, password='password123')
        # Unique constraint raises Integrity error
        with self.assertRaises(IntegrityError):
            self.user_model.objects.create_user(email=existing_email, password='password123')

    def test_create_user_with_existing_cellphone_fails(self) -> None:
        """Test creating user with existing cellphone fails."""
        existing_cellphone = '09000000000'
        self.user_model.objects.create_user(email='john@example.com', password='password123',
                                            cellphone=existing_cellphone)
        # Unique constraint raises Integrity error
        with self.assertRaises(IntegrityError):
            self.user_model.objects.create_user(email='jack@example.com', password='password123',
                                                cellphone=existing_cellphone)

    def test_user_post_save_signal_non_staff_user(self) -> None:
        """Test post save signal for user model doesn't create email device object for non staff."""
        user = self.user_model.objects.create_user(email='user@example.com', password='password123')

        self.assertFalse(user.emaildevice_set.exists())

    def test_user_post_save_signal_staff_user(self) -> None:
        """Test post save signal for user model creates email device object for staff."""
        user = self.user_model.objects.create_user(email='user@example.com', password='password123', is_staff=True)

        self.assertTrue(user.emaildevice_set.exists())


class PasswordRestCodeModelTests(TestCase):
    """Test PasswordRestCode model."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.user = get_user_model().objects.create_user(
            email='user@example.com',
            password='password123'
        )

    def test_creation_successful(self) -> None:
        """Test create PasswordResetCode successful."""
        password_reset_code = PasswordResetCode.objects.create(user=self.user)

        # Check expire timedelta works correctly
        self.assertAlmostEqual(
            round((password_reset_code.expires_at - password_reset_code.created).seconds / 60),
            settings.PASSWORD_RESET_CODE_EXPIRE_MINUTES)

        self.assertFalse(password_reset_code.is_expired())

        self.assertEqual(str(password_reset_code), password_reset_code.code)

    def test_creation_will_remove_old_objects(self) -> None:
        """Test creating a PasswordResetCode will remove previous objects."""
        PasswordResetCode.objects.create(user=self.user)
        password_reset_code2 = PasswordResetCode.objects.create(user=self.user)

        self.assertEqual(PasswordResetCode.objects.filter(user=self.user).count(), 1)
        self.assertEqual(self.user.password_reset_code.code, password_reset_code2.code)
        self.assertEqual(self.user.password_reset_code.id, password_reset_code2.id)

    def test_is_expired_method(self) -> None:
        """Test is_expired method works as expected."""
        prc = PasswordResetCode.objects.create(user=self.user)
        expires_at = prc.expires_at

        to_test = [
            expires_at + timedelta(seconds=1),
            expires_at + timedelta(minutes=1),
            expires_at + timedelta(minutes=58),
            expires_at + timedelta(days=1),
        ]
        # Patched timezone.now after creation of PasswordResetCode object because
        # it affects created field on model which uses timezone.now()
        with patch('account.models.timezone.now') as mocked_timezone_now:
            for fake_now in to_test:
                with self.subTest(fake_now=fake_now, expire_at=expires_at):
                    mocked_timezone_now.return_value = fake_now
                    self.assertTrue(prc.is_expired())
