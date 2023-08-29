from django.urls import path
from . import views

urlpatterns = [
    path('posts/', views.PostList.as_view(), name='post-list'),  # List and Create
    path('posts/<int:pk>/', views.PostDetail.as_view(), name='post-detail'),  # Retrieve, Update, Delete
]