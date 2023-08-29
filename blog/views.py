from rest_framework import generics
from .models import Post
from .serializer import PostSerializer
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import User

class PasswordAuthentication(BaseAuthentication):
    def authenticate(self, request):
        password = request.META.get('HTTP_PASSWORD')

        if password:
            # Verificar si la contraseña coincide con la del usuario deseado
            if password == '123456':
                return (User(), None)
            else:
                raise AuthenticationFailed('Contraseña incorrecta')
        
        return None

class PostList(generics.ListCreateAPIView):
    """
    Endpoint for listing and creating blog posts.

    - To list all posts:
      GET /api/posts/
    
    - To create a new post:
      POST /api/posts/
      Format: {"title": "Post Title", "content_md": "Markdown Content", "categories": [1, 2]}
    """
    authentication_classes = [PasswordAuthentication]
    permission_classes = [IsAuthenticated]
    queryset = Post.objects.all()
    serializer_class = PostSerializer

class PostDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Endpoint for retrieving, updating, and deleting a specific blog post.

    - To retrieve a post's details:
      GET /api/posts/{id}/
    
    - To update a post's details:
      PUT /api/posts/{id}/
      Format: {"title": "Updated Title", "content_md": "Updated Content", "categories": [1, 3]}
    
    - To delete a post:
      DELETE /api/posts/{id}/
    """
    authentication_classes = [PasswordAuthentication]
    permission_classes = [IsAuthenticated]
    queryset = Post.objects.all()
    serializer_class = PostSerializer

