from django.urls import path
from . import views

urlpatterns = [
    # Login / Register URLs
    path('register/', views.register, name='register'),  # Registro de usuario
    path('login/', views.login, name='login'),  # Inicio de sesión tradicional
    path('login-with-token/', views.login_with_token, name='login_with_token'),  # Inicio de sesión con token
    
    # Categories URLs
    path('categories/', views.list_categories, name='list_categories'),  # Listar todas las categorías
    path('categories/<int:category_id>/', views.view_category_with_notes, name='view_category_with_notes'),  # Ver detalles de una categoría y sus notas
    path('categories/create/', views.create_category, name='create_category'),  # Crear una nueva categoría
    path('categories/<int:category_id>/edit/', views.edit_category, name='edit_category'),  # Editar una categoría existente
    path('categories/<int:category_id>/delete/', views.delete_category, name='delete_category'),  # Eliminar una categoría
    
    # Notes URLs
    path('categories/<int:category_id>/notes/add/', views.add_note_to_category, name='add_note_to_category'),  # Agregar una nueva nota a una categoría
    path('categories/<int:category_id>/notes/', views.list_notes_in_category, name='list_notes_in_category'),  # Listar todas las notas en una categoría
    path('categories/<int:category_id>/notes/<int:note_id>/edit/', views.edit_note_in_category, name='edit_note_in_category'),  # Editar una nota en una categoría
    path('categories/<int:category_id>/notes/<int:note_id>/delete/', views.delete_note, name='delete_note'),  # Eliminar una nota
    path('categories/<int:category_id>/notes/<int:note_id>/', views.view_note, name='view_note'),  # Ver el contenido de una nota
]