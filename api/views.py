from rest_framework.decorators import action
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework import status
from datetime import datetime
from asgiref.sync import async_to_sync
from api.modules.misp_models_caller import (
    MispEventModules,
    MispAttibutesModules,
    MISPSearchModles,
    MispEventReportModules,
    MispTagsModules,
    MispObjectsModules, 
    MispFeedsModules
)

from .logs import LoggerService

logger = LoggerService()

class MISPEventsAPI(viewsets.ViewSet):
    def __init__(self):
        self.misp_class = MispEventModules()
    
    @action(detail=False, methods=['post'])
    def events_list(self, request):
        return async_to_sync(self._events_list)(request)
    
    @action(detail=False, methods=['post'])
    def add_event(self, request):
        return async_to_sync(self._add_event)(request)
    
    @action(detail=False, methods=['post'])
    def update_event(self, request):
        return async_to_sync(self._update_event)(request)
    
    @action(detail=False, methods=['post'])
    def get_event_list(self, request):
        return async_to_sync(self._get_event_list)(request)
    
    @action(detail=False, methods=['post'])
    def delete_event(self, request):
        return async_to_sync(self._delete_event)(request)
    
    
    
    async def _add_event(self, request):
        try:
            info = request.data.get("info") 
            analysis = request.data.get("analysis")
            threat_level_id = request.data.get("threat_level_id")
            if not info and not analysis and not threat_level_id:
                logger.error_log("MISPCallAPI", "add_event", None, "The fields are not entered correctly.")
                return Response({"Error": "Value Error"}, status=status.HTTP_400_BAD_REQUEST)
            
            created = await self.misp_class.add_event(info, analysis, threat_level_id)
            return Response({"Message": "Event Created", "Data": created}, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            logger.error_log("MISPCallAPI", "_add_event", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    async def _update_event(self, request):
        try:
            event_id = request.data.get("event_id")
            info = request.data.get("info") 
            analysis = request.data.get("analysis")
            threat_level_id = request.data.get("threat_level_id")
            
            if not info and not analysis and not threat_level_id:
                logger.error_log("MISPCallAPI", "_update_event", None, "The fields are not entered correctly.")
                return Response({"Error": "Value Error"}, status=status.HTTP_400_BAD_REQUEST)
            
            
            updated = await self.misp_class.update_event(event_id, info, analysis, threat_level_id)
            return Response({"Message": "Event updated on MISP", "Data": updated}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error_log("MISPCallAPI", "_update_event", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    async def _get_event_list(self, request):
        try:
            event_id = request.data.get("event_id")
            
            if not event_id:
                logger.error_log("MISPCallAPI", "_get_event_list", None, "The fields are not entered correctly.")
                return Response({"Error": "Value Error"}, status=status.HTTP_400_BAD_REQUEST)
            
            list_ = await self.misp_class.get_event(event_id)
            return Response({"Message": "Event Lists", "Data": list_}, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error_log("MISPCallAPI", "_get_event_list", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    async def _delete_event(self, request):
        try:
            event_id = request.data.get("event_id")
            
            deleted_obj = await self.misp_class.delete_event(event_id=event_id)
            return Response({"Message": f"Event {event_id} deleted .", "Data": deleted_obj}, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error_log("MISPCallAPI", "_delete_event", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    async def _events_list(self, request):
        try:
            list_ = await self. misp_class.events_list()
            return Response({"Message": f"Event Lists.", "Data": list_}, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error_log("MISPCallAPI", "_delete_event", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MISPAttibutesAPI(viewsets.ViewSet):
    def __init__(self):
        self.misp_class = MispAttibutesModules()
    
    @action(detail=False, methods=['post'])
    def attributes_list(self, request):
        return async_to_sync(self._attributes_list)(request)
    
    @action(detail=False, methods=['post'])
    def add_attr(self, request):
        return async_to_sync(self._add_attr)(request)

    @action(detail=False, methods=['post'])
    def update_attribute(self, request):
        return async_to_sync(self._update_attribute)(request)
    @action(detail=False, methods=['post'])
    def delete_attribute(self, request):
        return async_to_sync(self._delete_attribute)(request)

    @action(detail=False, methods=['post'])
    def get_attribute(self, request):
        return async_to_sync(self._get_attribute)(request)

    
    async def _attributes_list(self, request):
        try:
            list_ = await self. misp_class.attributes_list()
            return Response({"Message": f"Attribute Lists.", "Data": list_}, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error_log("MISPAttibutesAPI", "_attributes_list", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    async def _add_attr(self, request):
        try:

            if not request.data:
                logger.error_log("MISPAttibutesAPI", "_add_attr", None, "The fields are not entered correctly.")
                return Response({"Error": "Value Error"}, status=status.HTTP_400_BAD_REQUEST)
            
            event_id = request.data.get("event_id")
            value = request.data.get("value")
            category = request.data.get("category")
            type_val = request.data.get("type")
            first_seen = request.data.get("first_seen")
            last_seen = request.data.get("last_seen")
            disable_correlation = request.data.get("disable_correlation")
            

            created = await self.misp_class.add_attr(event_id, value, category, type_val, first_seen, last_seen, disable_correlation)
            return Response({"Message": "Event Created", "Data": created}, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            logger.error_log("MISPAttibutesAPI", "_add_attr", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    async def _update_attribute(self, request):
        try:

            if not request.data:
                logger.error_log("MISPAttibutesAPI", "_add_attr", None, "The fields are not entered correctly.")
                return Response({"Error": "Value Error"}, status=status.HTTP_400_BAD_REQUEST)
            
            attribute_id = request.data.get("attribute_id")
            value = request.data.get("value")
            category = request.data.get("category")
            type_val = request.data.get("type")
            first_seen = request.data.get("first_seen")
            last_seen = request.data.get("last_seen")
            disable_correlation = request.data.get("disable_correlation")
            

            updated = await self.misp_class.update_attribute(attribute_id, value, category, type_val, first_seen, last_seen, disable_correlation)
            return Response({"Message": "Attribute Updated", "Data": updated}, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error_log("MISPAttibutesAPI", "_update_attribute", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    async def _delete_attribute(self, request):
        try:

            if not request.data:
                logger.error_log("MISPAttibutesAPI", "_delete_attribute", None, "The fields are not entered correctly.")
                return Response({"Error": "Value Error"}, status=status.HTTP_400_BAD_REQUEST)
            
            attribute_id = request.data.get("attribute_id")

            deleted = await self.misp_class.delete_attribute(attribute_id)
            return Response({"Message": "Attribute deleted", "Data": deleted}, status=status.HTTP_204_NO_CONTENT)
        
        except Exception as e:
            logger.error_log("MISPAttibutesAPI", "_delete_attribute", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    async def _get_attribute(self, request):
        try:

            if not request.data:
                logger.error_log("MISPAttibutesAPI", "_get_attribute", None, "The fields are not entered correctly.")
                return Response({"Error": "Value Error"}, status=status.HTTP_400_BAD_REQUEST)
            
            attribute_id = request.data.get("attribute_id")


            obj = await self.misp_class.get_attribute(attribute_id)
            return Response({"Message": "Event Objects", "Data": obj}, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error_log("MISPAttibutesAPI", "_get_attribute", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
   
class MISPSearchAPI(viewsets.ViewSet):
    def __init__(self, **kwargs):
        self.misp_class = MISPSearchModles()
        
    @action(detail=False, methods=['post'])
    def search(self, request):
        return async_to_sync(self._search_misp)(request)
    
    async def _search_misp(self, request):
        try:
            controller = request.data.get("controller")
            kwargs = request.data.get("kwargs")
            list_ = await self. misp_class.search_misp(controller, kwargs)
            return Response({"Message": f"Search Response.", "Data": list_}, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error_log("MISPAttibutesAPI", "_search_misp", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class MISPEventReportAPI(viewsets.ViewSet):
    def __init__(self):
        self.misp_class = MispEventReportModules()
    
    @action(detail=False, methods=['post'])
    def add_event_report(self, request):
        return async_to_sync(self._add_event_report)(request)

    @action(detail=False, methods=['post'])
    def get_event_reports(self, request):
        return async_to_sync(self._get_event_reports)(request)

    @action(detail=False, methods=['post'])
    def update_event_report(self, request):
        return async_to_sync(self._update_event_report)(request)

    @action(detail=False, methods=['post'])
    def delete_event_report(self, request):
        return async_to_sync(self._delete_event_report)(request)


    async def _add_event_report(self, request):
        try:
            event_id = request.data.get('event_id')
            if not event_id:
                logger.error_log("MISPEventReposrtAPI", "_add_event_report", None, f"Value error from body")
            report_data = {
                "name": request.data.get("name"),
                "content": request.data.get("content"),
                "timestamp": request.data.get("timestamp"),
                "deleted": request.data.get("deleted")
            }
            obj = await self.misp_class.add_event_report(event_id, report_data)
            return Response({"Message": f"Event Report Added", "Data": obj}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error_log("MISPEventReposrtAPI", "_add_event_report", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    async def _get_event_reports(self, request):
        try:
            report_id = request.data.get('report_id')
            obj = await self.misp_class.get_event_reports(report_id)
            return Response({"Message": f"List of reports", "Data": obj}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error_log("MISPEventReposrtAPI", "_add_event_report", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    async def _update_event_report(self, request):
        try:
            report_id = request.data.get('report_id')
            if not report_id:
                logger.error_log("MISPEventReposrtAPI", "_add_event_report", None, f"Value error from body")
            report_data = {
                "name": request.data.get("name"),
                "content": request.data.get("content"),
                "timestamp": request.data.get("timestamp"),
                "deleted": request.data.get("deleted")
            }
            obj = await self.misp_class.update_event_report(report_id, report_data)
            return Response({"Message": f"Report updated", "Data": obj}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error_log("MISPEventReposrtAPI", "_update_event_report", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    async def _delete_event_report(self, request):
        try:
            report_id = request.data.get('report_id')
            if not report_id:
                logger.error_log("MISPEventReposrtAPI", "_add_event_report", None, f"Value error from body")
            obj = await self.misp_class.delete_event_report(report_id)
            return Response({"Message": f"Report deleted", "Data": obj}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error_log("MISPEventReposrtAPI", "_delete_event_report", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MISPTagsAPI(viewsets.ViewSet):
    def __init__(self):
        self.misp_class = MispTagsModules()
    
    @action(detail=False, methods=['post'])
    def add_tag(self, request):
        return async_to_sync(self._add_tag)(request)
    
    @action(detail=False, methods=['post'])
    def update_tag(self, request):
        return async_to_sync(self._update_tag)(request)

    @action(detail=False, methods=['post'])
    def delete_tag(self, request):
        return async_to_sync(self._delete_tag)(request)

    @action(detail=False, methods=['post'])
    def list_tag(self, request):
        return async_to_sync(self._list_tag)(request)

    @action(detail=False, methods=['post'])
    def get_tag(self, request):
        return async_to_sync(self._get_tag)(request)

    async def _add_tag(self, request):
        try:
            report_data = {
                "name": request.data.get("name"),
                "colour": request.data.get("colour"),
                "relationship_type": request.data.get("relationship_type"),
                "local": request.data.get("local")
            }
            obj = await self.misp_class.add_tag(report_data)
            return Response({"Message": f"Event Tag Added", "Data": obj}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error_log("MISPTagsAPI", "_add_tag", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    async def _update_tag(self, request):
        try:
            tag_id = request.data.get('tag_id')
            if not tag_id:
                logger.error_log("MISPTagsAPI", "_update_tag", None, f"Value error from body")
            report_data = {
                "name": request.data.get("name"),
                "content": request.data.get("content"),
                "timestamp": request.data.get("timestamp"),
                "deleted": request.data.get("deleted")
            }
            obj = await self.misp_class.update_tag(report_data, tag_id)
            return Response({"Message": f"Event Tag Updated", "Data": obj}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error_log("MISPTagsAPI", "_update_tag", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    async def _delete_tag(self, request):
        try:
            tag_id = request.data.get('tag_id')
            if not tag_id:
                logger.error_log("MISPTagsAPI", "_delete_tag", None, f"Value error from body")
            obj = await self.misp_class.delete_tag(tag_id)
            return Response({"Message": f"Event Tag Deleted", "Data": obj}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error_log("MISPTagsAPI", "_delete_tag", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    async def _list_tag(self, request):
        try:
            obj = await self.misp_class.list_tag()
            return Response({"Message": f"Event Tags List", "Data": obj}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error_log("MISPTagsAPI", "_list_tag", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    async def _get_tag(self, request):
        try:
            tag_id = request.data.get('tag_id')
            if not tag_id:
                logger.error_log("MISPTagsAPI", "_get_tag", None, f"Value error from body")
                
            obj = await self.misp_class.get_tag(tag_id)
            return Response({"Message": f"Event Tag with ID", "Data": obj}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error_log("MISPTagsAPI", "_get_tag", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MISPObjectsAPI(viewsets.ViewSet):
    def __init__(self):
        self.misp_class = MispObjectsModules()

    def timstamp_to_date(self, timestamp):
        dt_object = datetime.fromtimestamp(timestamp)
        return dt_object.strftime("%Y-%m-%d")

    @action(detail=False, methods=['post'])
    def add_obj(self, request):
        return async_to_sync(self._add_obj)(request)

    @action(detail=False, methods=['post'])
    def update_obj(self, request):
        return async_to_sync(self._update_obj)(request)

    @action(detail=False, methods=['post'])
    def get_obj(self, request):
        return async_to_sync(self._get_obj)(request)

    @action(detail=False, methods=['post'])
    def delete_obj(self, request):
        return async_to_sync(self._delete_obj)(request)


    async def _add_obj(self, request):
        try:
            from pymisp import MISPObject
            event_id = request.data.get('event_id')
            name = request.data.get("name")

            if not event_id or not name:
                return Response({"error": "Missing event_id or name"}, status=status.HTTP_400_BAD_REQUEST)

            misp_obj = MISPObject(name)
            misp_obj.comment = request.data.get("comment", "")
            misp_obj.first_seen = self.timstamp_to_date(request.data.get("first_seen"))
            misp_obj.last_seen = self.timstamp_to_date(request.data.get("last_seen"))

            attributes = request.data.get("attributes", [])
            for attr in attributes:
                object_relation = attr.get("object_relation")
                value = attr.get("value")
                if object_relation and value is not None:
                    misp_obj.add_attribute(object_relation, value)

            obj = await self.misp_class.add_obj(event_id, misp_obj.to_dict())
            return Response({"Message": "Event Objects Added", "Data": obj}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error_log("MISPObjectsAPI", "_add_obj", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    async def _update_obj(self, request):
        try:
            from pymisp import MISPObject
            obj_id = request.data.get('obj_id')
            name = request.data.get("name")

            if not obj_id or not name:
                return Response({"error": "Missing obj_id or name"}, status=status.HTTP_400_BAD_REQUEST)

            misp_obj = MISPObject(name)
            misp_obj.comment = request.data.get("comment", "")
            misp_obj.first_seen = self.timstamp_to_date(request.data.get("first_seen"))
            misp_obj.last_seen = self.timstamp_to_date(request.data.get("last_seen"))

            attributes = request.data.get("attributes", [])
            for attr in attributes:
                object_relation = attr.get("object_relation")
                value = attr.get("value")
                if object_relation and value is not None:
                    misp_obj.add_attribute(object_relation, value)

            obj = await self.misp_class.update_obj(obj_id, misp_obj.to_dict())
            return Response({"Message": "Event Objects Updated", "Data": obj}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error_log("MISPObjectsAPI", "_update_obj", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    async def _get_obj(self, request):
        try:
            obj_id = request.data.get('obj_id')
            obj = await self.misp_class.get_obj(obj_id)
            return Response({"Message": "Event Objects By ID", "Data": obj}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error_log("MISPObjectsAPI", "_get_obj", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    async def _delete_obj(self, request):
        try:
            obj_id = request.data.get('obj_id')
            obj = await self.misp_class.delete_obj(obj_id)
            return Response({"Message": "Event Objects Deleted By ID", "Data": obj}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error_log("MISPObjectsAPI", "_delete_obj", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MISPFeedsAPI(viewsets.ViewSet):
    def __init__(self):
        self.misp_class = MispFeedsModules()


    @action(detail=False, methods=['post'])
    def add_feed(self, request):
        return async_to_sync(self._add_feed)(request)

    @action(detail=False, methods=['post'])
    def update_feed(self, request):
        return async_to_sync(self._update_feed)(request)

    @action(detail=False, methods=['post'])
    def get_feed(self, request):
        return async_to_sync(self._get_feed)(request)

    @action(detail=False, methods=['post'])
    def feeds(self, request):
        return async_to_sync(self._feeds)(request)

    @action(detail=False, methods=['post'])
    def delete_feed(self, request):
        return async_to_sync(self._delete_feed)(request)


    async def _add_feed(self, request):
        try:
            feed_obj = request.data.get('feed_obj')
            obj = await self.misp_class.add_feed(feed_obj)
            return Response({"Message": "Feed Added", "Data": obj}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error_log("MISPFeedsAPI", "_add_feed", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    async def _update_feed(self, request):
        try:
            from pymisp import MISPObject
            feed_id = request.data.get('feed_id')
            feed_obj = request.data.get('feed_obj')
            obj = await self.misp_class.update_feed(feed_id, feed_obj.to_dict())
            return Response({"Message": "Feed Updated", "Data": obj}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error_log("MISPFeedsAPI", "_update_feed", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    async def _get_feed(self, request):
        try:
            feed_id = request.data.get('feed_id')
            obj = await self.misp_class.get_feed(feed_id)
            return Response({"Message": "Event Feed object", "Data": obj}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error_log("MISPFeedsAPI", "_get_feed", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    async def _delete_feed(self, request):
        try:
            feed_id = request.data.get('feed_id')
            obj = await self.misp_class.delete_feed(feed_id)
            return Response({"Message": "Event Objects Deleted By ID", "Data": obj}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error_log("MISPObjectsAPI", "_delete_feed", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    async def _feeds(self, request):
        try:
            obj = await self.misp_class.feeds()
            return Response({"Message": "Feeds list", "Data": obj}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error_log("MISPFeedsAPI", "_feeds", None, f"Unexpected error: {str(e)}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


