from celery import shared_task
from scheduler_project.celery import app
from django.core.mail import send_mail, get_connection, send_mass_mail
from django.core.mail import EmailMessage
from .models import Event, Polls
from django.contrib.auth.models import User
from datetime import datetime, timedelta
from django.template.loader import render_to_string
from django.template import loader
from django.shortcuts import get_object_or_404
from Crypto.Cipher import DES
from django.conf import settings


@shared_task
def deactive_poll():
    '''Funkcja wywoływana cyklicznie odpowiedzialna za ustanwianie pola if_active na False.
    Dezaktywuje ankiety na koniec dnia.
    Powinna być uruchamiana raz dziennie w nocy np. o 23:55.'''
    polls_list = Polls.objects.filter(if_active=True, till_active=datetime.now())
    if len(polls_list) == 0:
        pass
    else:
        for el in polls_list:
            el.if_active = False
            el.save()
    return None



