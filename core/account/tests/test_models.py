"""Test models for the accounts app."""
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase


class UserModelTests(TestCase):
    """Test user model."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.user_model = get_user_model()

    def test_create_user_success(self):
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

    def test_create_user_define_default_fields(self):
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

    def test_email_normalize_user_creation(self):
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

    def test_create_user_with_faulty_fields_raises_error(self):
        """Test creating user with faulty(empty/not defined) fields raises error."""
        with self.assertRaises(TypeError):
            self.user_model.objects.create_user()
        with self.assertRaises(TypeError):
            self.user_model.objects.create_user(email='')
        with self.assertRaises(ValueError):
            self.user_model.objects.create_user(email='', password='password123')

        user = self.user_model.objects.create_user(email='test@example.com', password='test123')
        self.assertFalse(hasattr(user, 'username'))

    def test_create_superuser(self):
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

    def test_create_superuser_with_faulty_fields_raises_error(self):
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

    def test_wrong_cellphone_raises_error(self):
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
