import unittest
from app.app import app
from flask import session

class TestRoutes(unittest.TestCase):
    def setUp(self):
        """Set up test client for Flask application."""
        self.app = app.test_client()
        self.app.testing = True

    def test_home_route(self):
        """Test the home route."""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'HUNT-AI', response.data)  # Check for specific content

    def test_methodology_routes(self):
        """Test methodology main route and sections."""
        response = self.app.get('/methodology')
        self.assertEqual(response.status_code, 200)
        response = self.app.get('/methodology/placeholder_title')  # Replace with actual valid title
        self.assertIn(response.status_code, [200, 404])  # Valid title returns 200, invalid returns 404

    def test_linux_routes(self):
        """Test Linux main route and sections."""
        response = self.app.get('/linux')
        self.assertEqual(response.status_code, 200)
        response = self.app.get('/linux/placeholder_title')  # Replace with actual valid title
        self.assertIn(response.status_code, [200, 404])

    def test_rule_creation_route(self):
        """Test rule creation route."""
        response = self.app.get('/rule_creation')
        self.assertEqual(response.status_code, 200)

    def test_windows_routes(self):
        """Test Windows main route and sections."""
        response = self.app.get('/windows')
        self.assertEqual(response.status_code, 200)
        response = self.app.get('/windows/placeholder_title')  # Replace with actual valid title
        self.assertIn(response.status_code, [200, 404])

    def test_investigate_routes(self):
        """Test investigate route and its subroutes."""
        response = self.app.get('/investigate')
        self.assertEqual(response.status_code, 200)

        for subroute in ['threat', 'domain', 'filehash', 'ip', 'malware']:
            response = self.app.get(f'/investigate/{subroute}')
            self.assertEqual(response.status_code, 200)

    def test_persistence_routes(self):
        """Test persistence menu and methods."""
        response = self.app.get('/persistence')
        self.assertEqual(response.status_code, 200)

        response = self.app.get('/persistence/valid_method')  # Replace with an actual valid method
        self.assertIn(response.status_code, [200, 404])

    

    def test_404_for_invalid_routes(self):
        """Test that invalid routes return a 404."""
        response = self.app.get('/this_route_does_not_exist')
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
