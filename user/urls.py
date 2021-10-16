from django.contrib import admin
from django.urls import path, include
from .views import *
urlpatterns = [
    path('signup', signup, name='signup'),
    path('loginProcess', loginProcess, name='loginProcess'),
    path('logoutProcess', logoutProcess, name='logoutProcess'),
    path('dashboard', dashboard, name='dashboard'),
    path('updatepassword', updatepassword, name='updatepassword'),
    path('forgetpassword', forgetpassword, name='forgetpassword'),
    path('confirmforgotPassword/<uidb64>/<token>/',confirmforgotPassword,name="confirmforgotPassword"),
    path('confirmforgotPasswordForm',confirmforgotPasswordForm,name="confirmforgotPasswordForm")


]