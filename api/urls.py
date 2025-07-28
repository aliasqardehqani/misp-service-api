from django.urls import path
from .views import *

urlpatterns = [
    # ---------------------------------------Publish-API`s------------------------------------------
    path('publish/', MISPPublishManagerAPI.as_view({'post': 'publish'}), name='publish'),
    path('unpublish/', MISPPublishManagerAPI.as_view({'post': 'unpublish'}), name='unpublish'),
    
    # ---------------------------------------Event-API`s--------------------------------------------
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
    
    # ----------------------------------------Tags-API`s---------------------------------------------
    path('add-tag/', MISPTagsAPI.as_view({'post': 'add_tag'}), name='add-tag'),
    path('update-tag/', MISPTagsAPI.as_view({'post': 'update_tag'}), name='update-tag'),
    path('delete-tag/', MISPTagsAPI.as_view({'post': 'delete_tag'}), name='delete-tag'),
    path('list-tag/', MISPTagsAPI.as_view({'post': 'list_tag'}), name='list-tag'),
    path('get-tag/', MISPTagsAPI.as_view({'post': 'get_tag'}), name='get-tag'),

    # ----------------------------------------Objects-API`s------------------------------------------
    path('add-obj/', MISPObjectsAPI.as_view({'post': 'add_obj'}), name='add-obj'),
    path('update-obj/', MISPObjectsAPI.as_view({'post': 'update_obj'}), name='update-obj'),
    path('get-obj/', MISPObjectsAPI.as_view({'post': 'get_obj'}), name='get-obj'),
    path('delete-obj/', MISPObjectsAPI.as_view({'post': 'delete_obj'}), name='delete-obj'),
    
    # ----------------------------------------Feeds-API`s--------------------------------------------
    path('add-feed/', MISPFeedsAPI.as_view({'post': 'add_feed'}), name='add-feed'),
    path('update-feed/', MISPFeedsAPI.as_view({'post': 'update_feed'}), name='update-feed'),
    path('delete-feed/', MISPFeedsAPI.as_view({'post': 'delete_feed'}), name='delete-feed'),
    path('list-feed/', MISPFeedsAPI.as_view({'post': 'feeds'}), name='list-feed'),
    path('get-feed/', MISPFeedsAPI.as_view({'post': 'get_feed'}), name='get-feed'),

    # ----------------------------------------Proposal-API`s--------------------------------------------
    path('add-attr-proposal/', MISPAttributeProposalAPI.as_view({'post': 'add_attribute_proposal'}), name='add-attr-proposal'),
    path('update-proposal/', MISPAttributeProposalAPI.as_view({'post': 'update_attribute_proposal'}), name='update-proposal'),
    path('delete-proposal/', MISPAttributeProposalAPI.as_view({'post': 'delete_attribute_proposal'}), name='delete-proposal'),
    path('list-proposal/', MISPAttributeProposalAPI.as_view({'post': 'attribute_proposals'}), name='list-proposal'),
    path('get-proposal/', MISPAttributeProposalAPI.as_view({'post': 'get_attribute_proposal'}), name='get-proposal'),

]














