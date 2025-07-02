from django.urls import path
from .views import (
    SignupView, VerifyEmailView, LoginView,
    UploadFileView, ListFilesView,
    GenerateDownloadLinkView, SecureDownloadView
)

urlpatterns = [
    path('signup/', SignupView.as_view()),
    path('verify-email/<str:token>/', VerifyEmailView.as_view()),
    path('login/', LoginView.as_view()),
    path('upload-file/', UploadFileView.as_view()),
    path('files/', ListFilesView.as_view()),
    path('download-file/<int:pk>/', GenerateDownloadLinkView.as_view()),
    path('secure-download/<str:token>/', SecureDownloadView.as_view()),
]
