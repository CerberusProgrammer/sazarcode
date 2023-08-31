from django.urls import path
from . import views

urlpatterns = [
    path('posts/', views.PostList.as_view(), name='post-list'),
    path('posts/<int:pk>/', views.PostDetail.as_view(), name='post-detail'),
    path('posts/category/<str:category_name>/', views.PostCategoryList.as_view(), name='post-category-list'),
    path('posts/categories/', views.CategoryList.as_view(), name='category-list'),
]