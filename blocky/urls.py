from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('login-with-token/', views.login_with_token, name='login_with_token'),
    # Otros patrones de URL aquí
]