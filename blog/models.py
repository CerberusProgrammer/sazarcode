from django.db import models

from django.db import models
from django.utils.html import mark_safe
import markdown

class Post(models.Model):
    title = models.CharField(max_length=200)
    content_md = models.TextField()
    publication_date = models.DateTimeField(auto_now_add=True)
    category = models.CharField(max_length=100)

    def __str__(self):
        return self.title

    def content_as_html(self):
        return mark_safe(markdown.markdown(self.content_md))
