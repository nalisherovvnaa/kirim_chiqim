from django.urls import path
from .views import (
    RegisterView,
    VerifyCodeView,
    LoginView,
    LogoutView,
    ProfileView,
    ChangePasswordView,
    ResetPasswordRequestView,
    SetNewPasswordView,
    )

urlpatterns = [
    path('register', RegisterView.as_view()),
    path('login', LoginView.as_view()),
    path('logout', LogoutView.as_view()),
    path('profile', ProfileView.as_view()),
    path('change-password', ChangePasswordView.as_view()),
    path('reset-password', ResetPasswordRequestView.as_view()),
    path('verify-code', VerifyCodeView.as_view()),
    path('set-new-password', SetNewPasswordView.as_view()),
]