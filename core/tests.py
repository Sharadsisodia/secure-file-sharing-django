from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from django.core.files.uploadedfile import SimpleUploadedFile
from .models import CustomUser, File

class FileSharingAPITestCase(APITestCase):
    def setUp(self):
        # Create users for both roles
        self.ops_user = CustomUser.objects.create_user(
            username='opsuser', email='ops@example.com', password='opspass',
            role='ops', email_verified=True
        )
        self.client_user = CustomUser.objects.create_user(
            username='clientuser', email='client@example.com', password='clientpass',
            role='client', email_verified=True
        )
        self.signup_url = '/api/signup/'
        self.login_url = '/api/login/'
        self.upload_url = '/api/upload-file/'
        self.files_url = '/api/files/'
        self.download_url = '/api/download-file/'
        self.secure_download_url = '/api/secure-download/'

    def authenticate(self, user):
        # Helper to authenticate as a user and set JWT token
        response = self.client.post(self.login_url, {
            "username": user.username,
            "password": "opspass" if user.role == "ops" else "clientpass"
        }, format='json')
        self.assertIn('access', response.data)
        token = response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

    def test_client_signup_and_email_verification(self):
        # Test client signup returns verify URL
        data = {
            "username": "newclient",
            "email": "newclient@example.com",
            "password": "newclientpass",
            "role": "client"
        }
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('verify_url', response.data)

        # Simulate email verification
        import re
        match = re.search(r'/api/verify-email/(.+)/', response.data['verify_url'])
        self.assertIsNotNone(match)
        token = match.group(1)
        verify_response = self.client.get(f'/api/verify-email/{token}/')
        self.assertEqual(verify_response.status_code, status.HTTP_200_OK)
        self.assertIn('Email verified', verify_response.data['message'])

    def test_ops_signup_auto_verified(self):
        # Test ops signup is auto-verified
        data = {
            "username": "newops",
            "email": "newops@example.com",
            "password": "newopspass",
            "role": "ops"
        }
        response = self.client.post(self.signup_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('Ops user created', response.data['message'])

    def test_login(self):
        # Test login for both users
        for user, pwd in [(self.ops_user, "opspass"), (self.client_user, "clientpass")]:
            response = self.client.post(self.login_url, {
                "username": user.username,
                "password": pwd
            }, format='json')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertIn('access', response.data)
            self.assertEqual(response.data['role'], user.role)

    def test_ops_can_upload_valid_file(self):
        self.authenticate(self.ops_user)
        file_content = b"dummy content"
        file = SimpleUploadedFile("test.docx", file_content, content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        response = self.client.post(self.upload_url, {'file': file}, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['filename'], "test.docx")

    def test_ops_cannot_upload_invalid_file(self):
        self.authenticate(self.ops_user)
        file_content = b"dummy content"
        file = SimpleUploadedFile("test.txt", file_content, content_type="text/plain")
        response = self.client.post(self.upload_url, {'file': file}, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_client_cannot_upload_file(self):
        self.authenticate(self.client_user)
        file_content = b"dummy content"
        file = SimpleUploadedFile("test.docx", file_content, content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        response = self.client.post(self.upload_url, {'file': file}, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_client_can_list_files(self):
        # First, upload a file as ops
        self.authenticate(self.ops_user)
        file_content = b"dummy content"
        file = SimpleUploadedFile("test.docx", file_content, content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        upload_response = self.client.post(self.upload_url, {'file': file}, format='multipart')
        self.assertEqual(upload_response.status_code, status.HTTP_201_CREATED)

        # Now, list files as client
        self.authenticate(self.client_user)
        response = self.client.get(self.files_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(any(f['filename'] == "test.docx" for f in response.data))

    def test_client_can_get_download_link_and_download(self):
        # Upload file as ops
        self.authenticate(self.ops_user)
        file_content = b"dummy content"
        file = SimpleUploadedFile("test.docx", file_content, content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        upload_response = self.client.post(self.upload_url, {'file': file}, format='multipart')
        file_id = upload_response.data['id']

        # Client requests download link
        self.authenticate(self.client_user)
        response = self.client.get(f"{self.download_url}{file_id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('download-link', response.data)
        import re
        match = re.search(r'/api/secure-download/(.+)/', response.data['download-link'])
        self.assertIsNotNone(match)
        token = match.group(1)

        # Client uses secure download link
        download_response = self.client.get(f"{self.secure_download_url}{token}/")
        self.assertEqual(download_response.status_code, status.HTTP_200_OK)
        self.assertEqual(download_response.get('Content-Disposition'), 'attachment; filename="test.docx"')

    def test_ops_cannot_use_client_download_link(self):
        # Upload file as ops
        self.authenticate(self.ops_user)
        file_content = b"dummy content"
        file = SimpleUploadedFile("test.docx", file_content, content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        upload_response = self.client.post(self.upload_url, {'file': file}, format='multipart')
        file_id = upload_response.data['id']

        # Client requests download link
        self.authenticate(self.client_user)
        response = self.client.get(f"{self.download_url}{file_id}/")
        import re
        match = re.search(r'/api/secure-download/(.+)/', response.data['download-link'])
        token = match.group(1)

        # Ops tries to use the client download link
        self.authenticate(self.ops_user)
        download_response = self.client.get(f"{self.secure_download_url}{token}/")
        self.assertEqual(download_response.status_code, status.HTTP_403_FORBIDDEN)

    def test_download_link_expiry(self):
        # This is a placeholder: to fully test expiry, we would need to mock datetime or set a very short expiry and wait.
        pass  # Implement with time mocking if needed

