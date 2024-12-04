import unittest
from app import app
from Blueprints.models import db, User
from flask import session


class TestTheming(unittest.TestCase):
    def setUp(self):
        """Set up test client and database for testing."""
        self.app = app.test_client()
        self.app.testing = True

        with app.app_context():
            # Drop and recreate the database tables to ensure a clean state
            db.drop_all()
            db.create_all()

            # Create a test user
            user = User(username="testuser", theme="dark")
            user.set_password("password")
            db.session.add(user)
            db.session.commit()

    def tearDown(self):
        """Clean up database after each test."""
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def login(self, username, password):
        """Helper method to log in a user."""
        return self.app.post('/login', data={
            'username': username,
            'password': password
        }, follow_redirects=True)

    def test_session_theme_default(self):
        """Test that the default theme is set in the session when visiting the home page."""
        with self.app as client:
            client.get('/')  # Visit the home page
            self.assertIn('theme', session)
            self.assertEqual(session['theme'], 'modern')

    def test_unauthenticated_theme_change_attempt(self):
        """Test that an unauthenticated user cannot change the theme."""
        # Attempt to access the profile page without logging in
        response = self.app.post('/profile', data={
            'theme': 'light',
            'role': '',  # Provide a default or valid value
        }, follow_redirects=False)  # Do not follow redirects to inspect the status code

        # Check for redirection to the login page
        self.assertEqual(response.status_code, 302)  # Should redirect to login
        self.assertIn('/login', response.location)  # Check the redirection target



if __name__ == "__main__":
    unittest.main()
