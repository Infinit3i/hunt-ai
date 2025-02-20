import unittest
import io  # Add this import at the top of your test file
import json  # Ensure json is imported
from app.app import app
from Blueprints.models import db, User
from werkzeug.security import generate_password_hash

class TestNotebookBlueprint(unittest.TestCase):
    def setUp(self):
        """Set up test client and database for testing."""
        self.app = app.test_client()
        self.app.testing = True

        with app.app_context():
            # Drop and recreate the database tables to ensure a clean state
            db.drop_all()
            db.create_all()

            # Create test users
            user1 = User(username="testuser1", theme="modern")
            user1.set_password("password1")  # Use set_password to hash the password
            user2 = User(username="testuser2", theme="light")
            user2.set_password("password2")  # Use set_password to hash the password

            db.session.add(user1)
            db.session.add(user2)
            db.session.commit()


    def test_notebook_route_unauthenticated(self):
        """Ensure unauthenticated users are redirected from the notebook route."""
        response = self.app.get('/notebook/')
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_notebook_route_authenticated(self):
        """Ensure authenticated users can access the notebook route."""
        with self.app:
            # Log in the user
            self.app.post('/login', data={
                'username': 'testuser1',
                'password': 'password1'
            }, follow_redirects=True)

            # Test access to the notebook route
            response = self.app.get('/notebook/')
            self.assertEqual(response.status_code, 200)
            
    def tearDown(self):
        """Clean up database after each test."""
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def login(self, username, password):
        """Helper method to log in a user."""
        return self.app.post('/login', data=dict(username=username, password=password), follow_redirects=True)

    def test_login_success(self):
        """Test that valid login works."""
        response = self.login("testuser1", "password1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Notebook', response.data)  # Ensure login redirects to a page with "Notebook"

    def test_login_failure(self):
        """Test that invalid login fails."""
        response = self.login("testuser1", "wrongpassword")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid username or password', response.data)
        
    def test_add_duplicate_entry(self):
        """Test that duplicate notebook entries are not allowed."""
        self.login("testuser1", "password1")
        self.app.post('/notebook/', data={
            'category': 'domains',
            'entry': 'example.com',
            'incident_time': '2024-12-01T12:00',
            'note': 'Example note',
        }, follow_redirects=True)
        response = self.app.post('/notebook/', data={
            'category': 'domains',
            'entry': 'example.com',  # Same entry as before
            'incident_time': '2024-12-02T12:00',
            'note': 'Duplicate note',
        }, follow_redirects=True)
        self.assertIn(b'Duplicate entry found', response.data)

    def test_import_notebook(self):
        """Test importing notebook data."""
        self.login("testuser1", "password1")
        data = {
            'domains': [
                {'data': 'example.com', 'incident_time': '2024-12-01T12:00', 'note': 'Example note'}
            ]
        }
        # Simulate a file upload using io.BytesIO
        file_content = io.BytesIO(json.dumps(data).encode('utf-8'))
        response = self.app.post('/notebook/import', data={
            'file': (file_content, 'notebook.json'),
        }, content_type='multipart/form-data', follow_redirects=True)
        self.assertIn(b'Notebook imported successfully', response.data)



if __name__ == "__main__":
    unittest.main()
