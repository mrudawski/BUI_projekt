from django.test import SimpleTestCase
from django.urls import reverse, resolve
from schedule.views import home_page, events_list, register_page


class TestUrls(SimpleTestCase):

    def test_home_resolves(self):
        url = reverse('home')
        self.assertEquals(resolve(url).func, home_page)

    def test_events_list_resolves(self):
        url = reverse('events_list')
        self.assertEquals(resolve(url).func, events_list)

    def test_register_page_resolves(self):
        url = reverse('register')
        self.assertEquals(resolve(url).func, register_page)

