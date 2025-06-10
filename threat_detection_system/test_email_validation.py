import unittest
import json
from app import app

class EmailValidationTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_valid_email_no_threat(self):
        response = self.app.post('/api/check_email', json={'email': 'user@gmail.com'})
        data = json.loads(response.data)
        self.assertTrue(data['valid'])
        self.assertFalse(data['threat'])
        self.assertIn('Email format is valid', data['message'])

    def test_valid_email_with_threat(self):
        response = self.app.post('/api/check_email', json={'email': 'user@gmaill.com'})
        data = json.loads(response.data)
        self.assertTrue(data['valid'])
        self.assertTrue(data['threat'])
        self.assertIn('Threat detected', data['message'])
        self.assertIn('suggestion', data)

    def test_invalid_email_format(self):
        response = self.app.post('/api/check_email', json={'email': 'user@@gmail..com'})
        data = json.loads(response.data)
        self.assertFalse(data['valid'])
        self.assertFalse(data['threat'])
        self.assertIn('Invalid email format', data['message'])

    def test_empty_email(self):
        response = self.app.post('/api/check_email', json={'email': ''})
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertIn('No email provided', data['error'])

if __name__ == '__main__':
    unittest.main()
