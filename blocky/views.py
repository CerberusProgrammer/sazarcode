# Django imports
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone

# REST imports
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny

# App imports
from blocky.models import Category, CustomUser, Note
from blocky.serializers import CategorySerializer, NoteSerializer

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'username': openapi.Schema(type=openapi.TYPE_STRING, description='User username'),
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
        }
    ),
    responses={201: 'User registered successfully', 400: 'Validation error', 500: 'Internal server error'}
)
@api_view(['POST'])
@authentication_classes([])  # No se requiere autenticación para esta vista
@permission_classes([AllowAny])  # Se permite a cualquier usuario acceder a esta vista
def register(request):
    """
    Register a new user.

    This endpoint allows users to register with a username, email, and password.

    Request Body:
        - username (str): User's desired username.
        - email (str): User's email.
        - password (str): User's desired password.

    Returns:
        - 201 User registered successfully: Registration was successful and a token is provided.
        - 400 Validation error: Validation error messages for invalid input.
        - 500 Internal server error: An error occurred during registration.
    """
    if request.method == 'POST':
        User = get_user_model()

        # Obtener los datos del request en formato JSON
        data = request.data
        username = data.get('username', '')
        email = data.get('email', '')
        password = data.get('password', '')

        try:
            # Validar el formato del correo electrónico
            User._meta.get_field('email').clean(email, User)

            # Validar la seguridad de la contraseña
            validate_password(password, user=User)
        except ValidationError as e:
            # Devolver mensajes de error de validación
            return Response({'message': e.messages}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Crear el usuario con contraseña encriptada
            user = User.objects.create_user(username=username, email=email, password=password)

            # Crear o recuperar el token de autenticación
            token, created = Token.objects.get_or_create(user=user)

            # Devolver respuesta exitosa con el token
            return Response({'message': 'User registered successfully', 'token': token.key}, status=status.HTTP_201_CREATED)
        except Exception as e:
            # Manejar excepciones generales, como problemas de base de datos
            return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='User password'),
        }
    ),
    responses={200: 'Login successful', 401: 'Invalid credentials'}
)
@api_view(['POST'])
@authentication_classes([])  # No se requiere autenticación para esta vista
@permission_classes([AllowAny])  # Se permite a cualquier usuario acceder a esta vista
def login(request):
    """
    Log in using email and password.

    This endpoint allows users to log in using their email and password.

    Request Body:
        - email (str): User's email.
        - password (str): User's password.

    Returns:
        - 200 Login successful: Login was successful and a token is provided.
        - 401 Invalid credentials: The provided email or password is invalid.
    """
    if request.method == 'POST':
        User = get_user_model()

        # Obtener los datos del request
        email = request.data.get('email', '')
        password = request.data.get('password', '')

        user = authenticate(request, email=email, password=password)

        if user:
            # Crear o recuperar el token de autenticación
            token, created = Token.objects.get_or_create(user=user)

            # Devolver respuesta exitosa con el token
            return Response({'message': 'Login successful', 'token': token.key, 'username': user.username})
        else:
            return Response({'message': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'token': openapi.Schema(type=openapi.TYPE_STRING, description='User token'),
        }
    ),
    responses={200: 'Login with token successful', 401: 'Invalid token'}
)
@api_view(['POST'])
@authentication_classes([])  # No se requiere autenticación para esta vista
@permission_classes([AllowAny])  # Se permite a cualquier usuario acceder a esta vista
def login_with_token(request):
    """
    Log in using a user token.

    This endpoint allows users to log in using a user token.

    Request Body:
        - token (str): User authentication token.

    Returns:
        - 200 Login with token successful: Login was successful with the provided token.
        - 401 Invalid token: The provided token is invalid.
    """
    if request.method == 'POST':
        User = get_user_model()

        # Obtener el token del request
        token = request.data.get('token', '')

        try:
            # Buscar el usuario asociado al token
            user = Token.objects.get(key=token).user

            # Devolver respuesta exitosa con el nombre de usuario
            return Response({'message': 'Login with token successful', 'username': user.username})
        except Token.DoesNotExist:
            return Response({'message': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'token': openapi.Schema(type=openapi.TYPE_STRING, description='User token'),
            'name': openapi.Schema(type=openapi.TYPE_STRING, description='Name of the category'),
            # Other properties required for creating a category
        }
    ),
    responses={201: 'Category created successfully', 400: 'Bad Request', 401: 'Unauthorized'}
)
@api_view(['POST'])
@authentication_classes([])  # No se requiere autenticación para esta vista
@permission_classes([AllowAny])  # Se permite a cualquier usuario acceder a esta vista
def create_category(request):
    """
    Create a new category.

    This endpoint allows users to create a new category.

    Query Parameters:
        - token (str): User authentication token.

    Request Body:
        - name (str): Name of the category.
        - Other properties required for creating a category.

    Returns:
        - 201 Category created successfully: Category was created successfully.
        - 400 Bad Request: The request body is not valid.
        - 401 Unauthorized: Authentication credentials were not provided or invalid token.
    """
    token = request.data.get('token', None)
    if not token:
        return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        user = Token.objects.get(key=token).user
    except Token.DoesNotExist:
        return Response({'detail': 'Invalid token.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    if request.method == 'POST':
        data = request.data.copy()
        data.pop('token', None)  # Quita 'token' del dict
        
        serialized_category = CategorySerializer(data=data)
        if serialized_category.is_valid():
            serialized_category.save(user=user)
            return Response(serialized_category.data, status=status.HTTP_201_CREATED)
        return Response(serialized_category.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='put',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'token': openapi.Schema(type=openapi.TYPE_STRING, description='User token'),
            'name': openapi.Schema(type=openapi.TYPE_STRING, description='Name of the category'),
            # Other properties that can be edited
        }
    ),
    responses={200: 'Category updated successfully', 400: 'Bad Request', 401: 'Unauthorized', 404: 'Category not found'}
)
@api_view(['PUT'])
@authentication_classes([])  # No se requiere autenticación para esta vista
@permission_classes([AllowAny])  # Se permite a cualquier usuario acceder a esta vista
def edit_category(request, category_id):
    """
    Edit a category.

    This endpoint allows users to edit the details of a category they own.

    Query Parameters:
        - token (str): User authentication token.

    Parameters:
        - category_id (int): ID of the category to be edited.

    Request Body:
        - name (str): Name of the category (optional).
        - Other properties that can be edited.

    Returns:
        - 200 Category updated successfully: Category was updated successfully.
        - 400 Bad Request: The request body is not valid.
        - 401 Unauthorized: Authentication credentials were not provided or invalid token.
        - 404 Category not found: The specified category was not found.
    """
    token = request.data.get('token', None)
    if token is None:
        return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        user = Token.objects.get(key=token).user
    except CustomUser.DoesNotExist:
        return Response({'detail': 'Invalid token.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        category = Category.objects.get(id=category_id, user=user)
    except Category.DoesNotExist:
        return Response({'message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serialized_category = CategorySerializer(category, data=request.data)
        if serialized_category.is_valid():
            serialized_category.save()

            # Refrescar los datos de la categoría editada
            category.refresh_from_db()

            # Devolver solo el category actualizado
            serialized_updated_category = CategorySerializer(category)

            return Response(serialized_updated_category.data, status=status.HTTP_200_OK)
        
        return Response(serialized_category.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='delete',
    manual_parameters=[
        openapi.Parameter('token', openapi.IN_QUERY, type=openapi.TYPE_STRING, description='User token'),
    ],
    responses={204: 'Category deleted successfully', 401: 'Unauthorized', 404: 'Category not found'}
)
@api_view(['DELETE'])
@authentication_classes([])  # No se requiere autenticación para esta vista
@permission_classes([AllowAny])  # Se permite a cualquier usuario acceder a esta vista
def delete_category(request, category_id):
    """
    Delete a category.

    This endpoint allows users to delete a category they own.

    Query Parameters:
        - token (str): User authentication token.

    Parameters:
        - category_id (int): ID of the category to be deleted.

    Returns:
        - 204 Category deleted successfully: Category was deleted successfully.
        - 401 Unauthorized: Authentication credentials were not provided or invalid token.
        - 404 Category not found: The specified category was not found.
    """
    token = request.data.get('token', None)
    if token is None:
        return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        user = Token.objects.get(key=token).user
    except CustomUser.DoesNotExist:
        return Response({'detail': 'Invalid token.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        category = Category.objects.get(id=category_id, user=user)
    except Category.DoesNotExist:
        return Response({'message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        category.delete()
        return Response({'message': 'Category deleted'}, status=status.HTTP_204_NO_CONTENT)

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('token', openapi.IN_QUERY, type=openapi.TYPE_STRING, description='User token'),
    ],
    responses={200: 'Categories retrieved successfully', 401: 'Unauthorized'}
)
@api_view(['GET'])
@authentication_classes([])  # No se requiere autenticación para esta vista
@permission_classes([AllowAny])  # Se permite a cualquier usuario acceder a esta vista
def list_categories(request):
    """
    List user categories.

    This endpoint allows users to retrieve a list of categories they own.

    Query Parameters:
        - token (str): User authentication token.

    Returns:
        - 200 Categories retrieved successfully: A list of categories owned by the user.
        - 401 Unauthorized: Authentication credentials were not provided or invalid token.
    """
    token = request.data.get('token', None)  # Obtener el token del JSON
    if token is None:
        return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        user = Token.objects.get(key=token).user
    except Token.DoesNotExist:
        return Response({'detail': 'Invalid token.'}, status=status.HTTP_401_UNAUTHORIZED)

    categories = Category.objects.filter(user=user)
    serialized_categories = CategorySerializer(categories, many=True)
    return Response(serialized_categories.data, status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'token': openapi.Schema(type=openapi.TYPE_STRING, description='User token'),
            'title': openapi.Schema(type=openapi.TYPE_STRING, description='Title of the note'),
            'content': openapi.Schema(type=openapi.TYPE_STRING, description='Content of the note'),
        },
        required=['token', 'title', 'content']
    ),
    responses={201: 'Created', 400: 'Bad Request', 401: 'Unauthorized'}
)
@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def add_note_to_category(request, category_id):
    """
    Add a new note to a specific category.

    This endpoint allows users to create a new note within a specified category.
    
    Request Parameters:
        - token (str): User authentication token.
        - title (str): Title of the note.
        - content (str): Content of the note.

    Returns:
        - 201 Created: The note was successfully created.
        - 400 Bad Request: Invalid input or missing parameters.
        - 401 Unauthorized: Authentication credentials were not provided.
    """
    token = request.data.get('token', None)
    if token is None:
        return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        user = Token.objects.get(key=token).user
    except CustomUser.DoesNotExist:
        return Response({'detail': 'Invalid token.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        category = Category.objects.get(id=category_id, user=user)
    except Category.DoesNotExist:
        return Response({'message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'POST':
        title = request.data.get('title')
        content = request.data.get('content')
        created_at = request.data.get('created_at')
        
        if created_at:
            try:
                created_at = timezone.strptime(created_at, '%d %b %Y')
            except ValueError:
                return Response({'message': 'Invalid date format for created_at'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            created_at = timezone.now()
        
        note = Note.objects.create(category=category, title=title, content=content, created_at=created_at)
        serialized_note = NoteSerializer(note)
        
        return Response(serialized_note.data, status=status.HTTP_201_CREATED)

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('token', openapi.IN_QUERY, type=openapi.TYPE_STRING, description='User token'),
    ],
    responses={200: 'Success', 401: 'Unauthorized', 404: 'Not Found'}
)
@api_view(['GET'])
@authentication_classes([])
@permission_classes([AllowAny])
def list_notes_in_category(request, category_id):
    """
    List notes in a specific category.

    This endpoint allows users to view a list of notes within a specified category.

    Query Parameters:
        - token (str): User authentication token.

    Returns:
        - 200 Success: List of notes within the specified category.
        - 401 Unauthorized: Authentication credentials were not provided or invalid token.
        - 404 Not Found: The specified category was not found.
    """
    token = request.data.get('token', None)
    if token is None:
        return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        user = Token.objects.get(key=token).user
    except CustomUser.DoesNotExist:
        return Response({'detail': 'Invalid token.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        category = Category.objects.get(id=category_id, user=user)
    except Category.DoesNotExist:
        return Response({'message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        notes = Note.objects.filter(category=category)
        serialized_notes = NoteSerializer(notes, many=True)
        return Response(serialized_notes.data, status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('token', openapi.IN_QUERY, type=openapi.TYPE_STRING, description='User token'),
    ],
    responses={200: 'Success', 401: 'Unauthorized', 404: 'Not Found'}
)
@api_view(['GET'])
@authentication_classes([])
@permission_classes([AllowAny])
def view_category_with_notes(request, category_id):
    """
    View category details with associated notes.

    This endpoint allows users to view details of a specific category along with its associated notes.

    Query Parameters:
        - token (str): User authentication token.

    Returns:
        - 200 Success: Details of the category along with its notes.
        - 401 Unauthorized: Authentication credentials were not provided or invalid token.
        - 404 Not Found: The specified category was not found.
    """
    token = request.data.get('token', None)
    if token is None:
        return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        user = Token.objects.get(key=token).user
    except CustomUser.DoesNotExist:
        return Response({'detail': 'Invalid token.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        category = Category.objects.get(id=category_id, user=user)
        serialized_category = CategorySerializer(category)
        
        notes = Note.objects.filter(category=category)
        serialized_notes = NoteSerializer(notes, many=True)
        
        response_data = {
            'category': serialized_category.data,
            'notes': serialized_notes.data
        }
        return Response(response_data, status=status.HTTP_200_OK)
    except Category.DoesNotExist:
        return Response({'message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)

@swagger_auto_schema(
    method='put',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'token': openapi.Schema(type=openapi.TYPE_STRING, description='User token'),
            'title': openapi.Schema(type=openapi.TYPE_STRING, description='New title of the note'),
            'content': openapi.Schema(type=openapi.TYPE_STRING, description='New content of the note'),
            'created_at': openapi.Schema(type=openapi.TYPE_STRING, description='New creation date of the note (optional)'),
        }
    ),
    responses={200: 'Note updated successfully', 401: 'Unauthorized', 404: 'Not Found', 400: 'Bad Request'}
)
@api_view(['PUT'])
@authentication_classes([])
@permission_classes([AllowAny])
def edit_note_in_category(request, category_id, note_id):
    """
    Edit a note in a category.

    This endpoint allows users to edit the details of a specific note within a category.

    Query Parameters:
        - token (str): User authentication token.

    Request Body:
        - title (str): New title of the note.
        - content (str): New content of the note.
        - created_at (str, optional): New creation date of the note (optional, format: 'dd MMM YYYY').

    Returns:
        - 200 Note updated successfully: Updated details of the note.
        - 401 Unauthorized: Authentication credentials were not provided or invalid token.
        - 404 Not Found: The specified category or note was not found.
        - 400 Bad Request: Invalid date format for created_at or other input validation issues.
    """
    token = request.data.get('token', None)
    if token is None:
        return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        user = Token.objects.get(key=token).user
    except CustomUser.DoesNotExist:
        return Response({'detail': 'Invalid token.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        category = Category.objects.get(id=category_id, user=user)
    except Category.DoesNotExist:
        return Response({'message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)
    
    try:
        note = Note.objects.get(id=note_id, category=category)
    except Note.DoesNotExist:
        return Response({'message': 'Note not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        title = request.data.get('title')
        content = request.data.get('content')
        created_at = request.data.get('created_at')
        
        if created_at:
            try:
                created_at = timezone.strptime(created_at, '%d %b %Y')
            except ValueError:
                return Response({'message': 'Invalid date format for created_at'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            created_at = timezone.now()
        
        note.title = title
        note.content = content
        note.created_at = created_at
        note.save()
        
        serialized_note = NoteSerializer(note)
        return Response(serialized_note.data, status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='delete',
    manual_parameters=[
        openapi.Parameter('token', openapi.IN_QUERY, type=openapi.TYPE_STRING, description='User token'),
    ],
    responses={204: 'Note deleted successfully', 401: 'Unauthorized', 404: 'Not Found'}
)
@api_view(['DELETE'])
@authentication_classes([])
@permission_classes([AllowAny])
def delete_note(request, category_id, note_id):
    """
    Delete a note.

    This endpoint allows users to delete a specific note within a category.

    Query Parameters:
        - token (str): User authentication token.

    Returns:
        - 204 Note deleted successfully: The note was deleted successfully.
        - 401 Unauthorized: Authentication credentials were not provided or invalid token.
        - 404 Not Found: The specified category or note was not found.
    """
    token = request.data.get('token', None)
    if token is None:
        return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        user = Token.objects.get(key=token).user
    except CustomUser.DoesNotExist:
        return Response({'detail': 'Invalid token.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        category = Category.objects.get(id=category_id, user=user)
    except Category.DoesNotExist:
        return Response({'message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)
    
    try:
        note = Note.objects.get(id=note_id, category=category)
        note.delete()
        return Response({'message': 'Note deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    except Note.DoesNotExist:
        return Response({'message': 'Note not found'}, status=status.HTTP_404_NOT_FOUND)

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('token', openapi.IN_QUERY, type=openapi.TYPE_STRING, description='User token'),
    ],
    responses={200: 'Note retrieved successfully', 401: 'Unauthorized', 404: 'Not Found'}
)
@api_view(['GET'])
@authentication_classes([])
@permission_classes([AllowAny])
def view_note(request, category_id, note_id):
    """
    Retrieve a note.

    This endpoint allows users to retrieve the details of a specific note within a category.

    Query Parameters:
        - token (str): User authentication token.

    Returns:
        - 200 Note retrieved successfully: The details of the note.
        - 401 Unauthorized: Authentication credentials were not provided or invalid token.
        - 404 Not Found: The specified category or note was not found.
    """
    token = request.data.get('token', None)
    if token is None:
        return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        user = Token.objects.get(key=token).user
    except CustomUser.DoesNotExist:
        return Response({'detail': 'Invalid token.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        category = Category.objects.get(id=category_id, user=user)
    except Category.DoesNotExist:
        return Response({'message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)
    
    try:
        note = Note.objects.get(id=note_id, category=category)
        serialized_note = NoteSerializer(note)
        return Response(serialized_note.data, status=status.HTTP_200_OK)
    except Note.DoesNotExist:
        return Response({'message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)
