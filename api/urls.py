from django.urls import path
from .views import *

urlpatterns = [
    path('add-event/', MISPEventsAPI.as_view({'post': 'add_event'}), name='add-event'),
    path('get-event/', MISPEventsAPI.as_view({'post': 'get_event_list'}), name='get-event-list'),
    path('update-event/', MISPEventsAPI.as_view({'post': 'update_event'}), name='update-event'),
    path('delete-event/', MISPEventsAPI.as_view({'post': 'delete_event'}), name='delete-event'),
    path('list-event/', MISPEventsAPI.as_view({'post': 'events_list'}), name='list-event'),
    
    # ---------------------------------------Attribute-API`s----------------------------------------
    path('list-attr/', MISPAttibutesAPI.as_view({'post': 'attributes_list'}), name='list-attr'),
    path('add-attr/', MISPAttibutesAPI.as_view({'post': 'add_attr'}), name='add-attr'),
    path('update-attr/', MISPAttibutesAPI.as_view({'post': 'update_attribute'}), name='update-attr'),
    path('delete-attr/', MISPAttibutesAPI.as_view({'post': 'delete_attribute'}), name='delete-attr'),
    path('get-attr/', MISPAttibutesAPI.as_view({'post': 'get_attribute'}), name='get-attr'),
    
    # ----------------------------------------Search-API`s------------------------------------------
    path('search/', MISPSearchAPI.as_view({'post': 'search'}), name='search'),
    
    # ----------------------------------------Search-API`s------------------------------------------
    path("add-report/", MISPEventReportAPI.as_view({'post': 'add_event_report'}), name='add-event-report'),
    path("get-reports/", MISPEventReportAPI.as_view({'post': 'get_event_reports'}), name='get-event-reports'),
    path("update-report/", MISPEventReportAPI.as_view({'post': 'update_event_report'}), name='update-event-report'),
    path("delete-report/", MISPEventReportAPI.as_view({'post': 'delete_event_report'}), name='delete-event-report'),
]






