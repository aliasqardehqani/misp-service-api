from rest_framework.decorators import action
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework import status

from asgiref.sync import async_to_sync
from api.modules.misp_models_caller import MispEventModules, MispAttibutesModules, MISPSearchModles

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
        
