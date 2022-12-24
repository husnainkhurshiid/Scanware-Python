from django.db import models

# Create your models here.
class FilestoScan(models.Model):
    file = models.FileField()
    f = models
    class meta:
        verbose_name_plural = 'FilesToScan'

    def __str__(self):
        return self.file