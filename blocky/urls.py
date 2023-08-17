from django.urls import path
from . import views

urlpatterns = [
    # Login / Register URLs
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('login-with-token/', views.login_with_token, name='login_with_token'),
    # Categories URLs
    path('categories/', views.list_categories, name='list_categories'),
    path('categories/create/', views.create_category, name='create_category'),
    path('categories/<int:category_id>/edit/', views.edit_category, name='edit_category'),
    path('categories/<int:category_id>/delete/', views.delete_category, name='delete_category'),
    # Notes URLs
    path('categories/<int:category_id>/notes/add/', views.add_note_to_category, name='add_note_to_category'),
    path('categories/<int:category_id>/notes/', views.list_notes_in_category, name='list_notes_in_category'),
    path('categories/<int:category_id>/notes/<int:note_id>/edit/', views.edit_note_in_category, name='edit_note_in_category'),
    path('categories/<int:category_id>/notes/<int:note_id>/delete/', views.edit_note_in_category, name='edit_note_in_category'),
] 