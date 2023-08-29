from rest_framework import serializers
from django.utils.html import mark_safe
from .models import Post
import markdown

class PostSerializer(serializers.ModelSerializer):
    content_html = serializers.SerializerMethodField()  # Field to hold the HTML content

    class Meta:
        model = Post
        fields = '__all__'

    def get_content_html(self, obj):
        return mark_safe(markdown.markdown(obj.content_md))  # Convert Markdown to HTML and mark as safe
