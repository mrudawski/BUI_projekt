from django.test import TestCase, Client
from django.urls import reverse
from schedule.models import Event
import json


class TestViews(TestCase):

    def test_events_list_GET(self):
        client = Client()

        response = client.get(reverse('events_list'))

        self.assertEquals(response.status_code, 200)
        self.assertTemplateUsed(response, 'schedule/events_list.html')

