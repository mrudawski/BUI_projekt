from celery import app as celery_app

__all__ = ('celery_app',)

#2 FA

default_app_config = 'schedule.apps.ScheduleConfig'