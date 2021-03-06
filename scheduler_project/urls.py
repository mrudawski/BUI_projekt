
"""scheduler_project URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path, include

handler403 = 'schedule.views.handler_403'
handler404 = 'schedule.views.handler_404'
handler400 = 'schedule.views.handler_400'
handler500 = 'schedule.views.handler_500'

urlpatterns = [

     path('', include('schedule.urls')),

 ]
