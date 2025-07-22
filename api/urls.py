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
    path('search/', MISPAttibutesAPI.as_view({'post': 'search'}), name='search'),
]


