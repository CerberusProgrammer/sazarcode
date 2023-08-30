from rest_framework import generics
from .models import Post
from .serializer import PostSerializer
from rest_framework.permissions import IsAuthenticated

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import User
from rest_framework.response import Response

from decouple import config

class PasswordAuthentication(BaseAuthentication):
    def authenticate(self, request):
        password = request.META.get('HTTP_PASSWORD')
        correct_password = config('PASSWORD', default='default_password')
        print(correct_password)

        if password:
            if password == correct_password:
                return (User(), None)
            else:
                raise AuthenticationFailed('Incorrect password')
        
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

class CategoryList(generics.ListAPIView):
    """
    Endpoint for listing unique categories.

    - To list unique categories:
      GET /api/categories/
    """
    authentication_classes = [PasswordAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request, *args, **kwargs):
        categories = Post.objects.values_list('category', flat=True).distinct()
        return Response(categories)

class PostCategoryList(generics.ListAPIView):
    """
    Endpoint for listing blog posts by category.

    - To list posts by category:
      GET /api/posts/category/{category_name}/
    """
    authentication_classes = [PasswordAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = PostSerializer

    def get_queryset(self):
        category_name = self.kwargs['category_name']
        queryset = Post.objects.filter(category__iexact=category_name)
        return queryset

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

