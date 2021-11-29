from django.db import models
from django.contrib.auth.models import User, Group
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.utils.text import slugify

import random
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.dispatch import receiver
from django.db.models.signals import post_migrate
from django.contrib.auth import get_user_model


class Event(models.Model):
    STATUS_CHOICES = (
        ('draft', 'Szkic'),
        ('publish', 'Opublikowano')
    )
    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=250,
                            unique_for_date='planning_date', default=None)
    description = models.TextField(verbose_name='opis wydarzenia', blank=True, max_length=1000)
    created = models.DateTimeField(auto_now_add=True)
    planning_date = models.DateTimeField(blank=True, null=True)
    publish = models.DateTimeField(default=timezone.now)
    organizer = models.ForeignKey(User, on_delete=models.CASCADE)
    want_to_listen = models.ManyToManyField(User, related_name='want_to_listen', default=None, blank=True, null=True)
    status = models.CharField(max_length=15,
                              choices=STATUS_CHOICES,
                              default='publish')
    duration = models.IntegerField(blank=True, null=True)
    icon = models.FileField(upload_to='icons/', default='icons/default.png', null=True)
    attachment = models.FileField(upload_to='attachments/', blank=True, null=True)
    link = models.CharField(max_length=1000, blank=True, null=True)

    def save(self, *args, **kwargs):
        self.slug = slugify(self.title)
        super(Event, self).save(*args, **kwargs)

    # topics

    class Meta:
        ordering = ('planning_date',)

    def __str__ (self):
        return self.title


class Comment(models.Model):
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    event = models.ForeignKey(Event, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)
    content = models.TextField(max_length=1000)
    if_edited = models.BooleanField(default=False)
    if_deleted = models.BooleanField(default=False)

    class Meta:
        ordering = ('-created',)

# Needed for 2FA
# class Code(models.Model):
#     verification_code = models.CharField(max_length=5, blank=True)
#     user = models.OneToOneField(User, on_delete=models.CASCADE)
#     def __str__(self):
#         return str(self.verification_code)
#
#     def save(self, *args, **kwargs):
#         number_list = [0,1,2,3,4,5,6,7,8,9]
#         code_items = []
#         for i in range(5):
#             num = random.choice(number_list)
#             code_items.append(num)
#         code_string = "".join(str(item) for item in code_items)
#         self.verification_code =  code_string
#         super().save(*args, **kwargs)