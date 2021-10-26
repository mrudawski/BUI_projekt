from celery import shared_task
from scheduler_project.celery import app
from django.core.mail import send_mail, get_connection, send_mass_mail
from django.core.mail import EmailMessage
from .models import Event
from django.contrib.auth.models import User
from datetime import datetime, timedelta
from django.template.loader import render_to_string
from django.template import loader
from django.shortcuts import get_object_or_404
from Crypto.Cipher import DES
from django.conf import settings
