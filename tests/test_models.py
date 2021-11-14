import datetime
from django.test import TestCase, Client
from schedule.models import Event, Comment


class TestModels(TestCase):

    def setUp(self):
        self.event1 = Event.objects.create(
            title='Title',
            slug='Slug',
            description='Description',
            created=datetime.datetime.now(),
            planning_date=datetime.datetime.now(),
            publish=datetime.datetime.now(),
            organizer=self.user1
            )

    def test_event