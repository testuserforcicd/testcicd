"""
URL configuration for waf_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from accounts.views import register_view, verify_email, dashboard_view, setup_2fa, verify_2fa_setup, verify_otp_login
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', register_view, name='register'),
    path('verify/<str:token>/', verify_email, name='verify_email'),
    path('login/', auth_views.LoginView.as_view(template_name='accounts/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('accounts/', include('allauth.urls')),
    path('2fa/setup/', setup_2fa, name='setup_2fa'),
    path('2fa/verify/', verify_2fa_setup, name='verify_2fa_setup'),
    path('verify-2fa/', verify_otp_login, name='verify_otp_login'),
]
