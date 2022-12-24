from django.contrib import admin
from .models import FilestoScan
# Register your models here.

admin.site.register(FilestoScan)

class FileModelAdmin(admin.ModelAdmin):
    list_display = ['id','File']