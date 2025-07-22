from django.urls import path
from .views import *

urlpatterns = [
    path('add-event/', MISPCallAPI.as_view({'post': 'add_event'}), name='add-event'),
    path('get-event/', MISPCallAPI.as_view({'post': 'get_event_list'}), name='get-event-list'),
    path('update-event/', MISPCallAPI.as_view({'post': 'update_event'}), name='update-event'),
    path('delete-event/', MISPCallAPI.as_view({'post': 'delete_event'}), name='delete-event'),
    path('list-event/', MISPCallAPI.as_view({'post': 'events_list'}), name='list-event'),
]


