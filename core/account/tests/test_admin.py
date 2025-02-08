"""Test admin of account app."""
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model


class UserAdminTests(TestCase):
    """Test user app admin."""

    @classmethod
    def setUpTestData(cls):
        cls.client = Client()
        cls.admin_user = get_user_model().objects.create_superuser(
            email='admin@example.com',
            password='password123',
        )
        cls.user = get_user_model().objects.create_user(
            email='user@example.com',
            password='password123',
            first_name='John',
            last_name='Doe',
            cellphone='09000000000',
        )

    def setUp(self):
        self.client.force_login(self.admin_user)

    def test_user_admin_page_loads_success(self):
        """Test user admin change_list page loads successfully."""
        url = reverse('admin:account_user_changelist')
        res = self.client.get(url)

        self.assertEqual(res.status_code, 200)
        self.assertContains(res, self.user.email)
        self.assertContains(res, self.user.first_name)
        self.assertContains(res, self.user.last_name)

    def test_user_admin_search_fields(self):
        """Test user admin search functionality by
         email, first_name, last_name."""
        url = reverse('admin:account_user_changelist')
        search_queries = [
            ['user@example', self.user.email],
            ['joh', self.user.first_name],
            ['Doe', self.user.last_name],
        ]
        for query, expected in search_queries:
            with self.subTest(query=query):
                res = self.client.get(url, {'q': query})
                self.assertEqual(res.status_code, 200)
                self.assertContains(res, expected)
