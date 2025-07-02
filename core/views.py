from django.shortcuts import render

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics, permissions
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.conf import settings
from .models import CustomUser, File
from .serializers import UserSignupSerializer, FileSerializer
from .permissions import IsOpsUser, IsClientUser
from .utils import generate_token, decode_token
import os

# Signup (role-based)
class SignupView(APIView):
    def post(self, request):
        serializer = UserSignupSerializer(data=request.data)
        if serializer.is_valid():
            role = serializer.validated_data.get('role')
            if role not in ['client', 'ops']:
                return Response({'error': 'Role must be "client" or "ops".'}, status=400)
            user = serializer.save()
            # For demo: only client gets email verification, ops is auto-verified
            if role == 'client':
                token = generate_token({'user_id': user.id}, expiry_minutes=60)
                verify_url = f"{request.build_absolute_uri('/api/verify-email/')}{token}/"
                send_mail(
                    'Verify your email',
                    f'Click the link to verify your email: {verify_url}',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                return Response({'message': 'User created. Please verify your email.', 'verify_url': verify_url}, status=201)
            else:
                user.email_verified = True
                user.save()
                return Response({'message': 'Ops user created and verified.'}, status=201)
        return Response(serializer.errors, status=400)

# Email Verification
class VerifyEmailView(APIView):
    def get(self, request, token):
        payload = decode_token(token)
        if not payload:
            return Response({'message': 'Invalid or expired token.'}, status=400)
        user_id = payload['user_id']
        try:
            user = CustomUser.objects.get(id=user_id)
            user.email_verified = True
            user.save()
            return Response({'message': 'Email verified successfully.'})
        except CustomUser.DoesNotExist:
            return Response({'message': 'User not found.'}, status=404)

# Login
class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user:
            if user.role == 'client' and not user.email_verified:
                return Response({'message': 'Email not verified.'}, status=400)
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'role': user.role
            })
        return Response({'message': 'Invalid credentials.'}, status=400)

# Upload File (Ops only)
class UploadFileView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsOpsUser]
    def post(self, request):
        file_obj = request.FILES.get('file')
        if not file_obj:
            return Response({'message': 'No file provided.'}, status=400)
        ext = os.path.splitext(file_obj.name)[1].lower()
        if ext not in ['.ppt', '.doc', '.xls']:
            return Response({'message': 'Invalid file type.'}, status=400)
        file_instance = File.objects.create(
            uploader=request.user,
            file=file_obj,
            filename=file_obj.name
        )
        return Response(FileSerializer(file_instance).data, status=201)

# List Files (Client only)
class ListFilesView(generics.ListAPIView):
    serializer_class = FileSerializer
    permission_classes = [permissions.IsAuthenticated, IsClientUser]
    queryset = File.objects.all()

# Generate Download Link (Client only)
class GenerateDownloadLinkView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsClientUser]
    def get(self, request, pk):
        try:
            file = File.objects.get(id=pk)
        except File.DoesNotExist:
            return Response({'message': 'File not found.'}, status=404)
        token = generate_token({'file_id': file.id, 'user_id': request.user.id}, expiry_minutes=15)
        download_link = f"{request.build_absolute_uri('/api/secure-download/')}{token}/"
        return Response({'download-link': download_link, 'message': 'success'})

# Secure Download (Client only)
from django.http import FileResponse, Http404

class SecureDownloadView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsClientUser]
    def get(self, request, token):
        payload = decode_token(token)
        if not payload:
            return Response({'message': 'Invalid or expired token.'}, status=400)
        file_id = payload['file_id']
        user_id = payload['user_id']
        if user_id != request.user.id:
            return Response({'message': 'Access denied.'}, status=403)
        try:
            file = File.objects.get(id=file_id)
        except File.DoesNotExist:
            raise Http404
        return FileResponse(file.file, as_attachment=True, filename=file.filename)
