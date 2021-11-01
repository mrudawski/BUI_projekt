from django.test import TestCase
from schedule.models import Event

class TestModels(TestCase):

    def setUp(self):
        self.event1 = Event.objects.create(

        )