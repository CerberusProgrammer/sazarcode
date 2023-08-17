from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password

from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated

from blocky.models import Category, CustomUser
from blocky.serializers import CategorySerializer

@api_view(['POST'])
@authentication_classes([])  # No se requiere autenticación para esta vista
@permission_classes([AllowAny])  # Se permite a cualquier usuario acceder a esta vista
def register(request):
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

@api_view(['POST'])
@authentication_classes([])  # No se requiere autenticación para esta vista
@permission_classes([AllowAny])  # Se permite a cualquier usuario acceder a esta vista
def login(request):
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

@api_view(['POST'])
@authentication_classes([])  # No se requiere autenticación para esta vista
@permission_classes([AllowAny])  # Se permite a cualquier usuario acceder a esta vista
def login_with_token(request):
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

@api_view(['POST'])
@authentication_classes([])  # No se requiere autenticación para esta vista
@permission_classes([AllowAny])  # Se permite a cualquier usuario acceder a esta vista
def create_category(request):
    print(request.data)
    token = request.data.get('token', None)
    
    if token is None:
        return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        user = CustomUser.objects.get(token=token)
    except CustomUser.DoesNotExist:
        return Response({'detail': 'Invalid token.'}, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == 'POST':
        serialized_category = CategorySerializer(data=request.data)
        if serialized_category.is_valid():
            serialized_category.save(user=user)
            return Response(serialized_category.data, status=status.HTTP_201_CREATED)
        return Response(serialized_category.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def edit_category(request, category_id):
    user = request.user

    token = request.data.get('token', None)  # Obtener el token del JSON
    if token is None:
        return Response({'message': 'Token not provided'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        category = Category.objects.get(id=category_id, user=user)
    except Category.DoesNotExist:
        return Response({'message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serialized_category = CategorySerializer(category, data=request.data)
        if serialized_category.is_valid():
            serialized_category.save()
            return Response(serialized_category.data, status=status.HTTP_200_OK)
        return Response(serialized_category.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_category(request, category_id):
    user = request.user

    token = request.data.get('token', None)  # Obtener el token del JSON
    if token is None:
        return Response({'message': 'Token not provided'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        category = Category.objects.get(id=category_id, user=user)
    except Category.DoesNotExist:
        return Response({'message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'DELETE':
        category.delete()
        return Response({'message': 'Category deleted'}, status=status.HTTP_204_NO_CONTENT)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_categories(request):
    user = request.user

    token = request.data.get('token', None)  # Obtener el token del JSON
    if token is None:
        return Response({'message': 'Token not provided'}, status=status.HTTP_400_BAD_REQUEST)
    
    categories = Category.objects.filter(user=user)
    serialized_categories = CategorySerializer(categories, many=True)
    return Response(serialized_categories.data, status=status.HTTP_200_OK)
