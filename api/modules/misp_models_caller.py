import asyncio
from pymisp import PyMISP, MISPEvent, MISPAttribute
from django.conf import settings
from pprint import pprint
from datetime import datetime
from zoneinfo import ZoneInfo
from api.logs import LoggerService

logger = LoggerService

class MispPublishManagerModules:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)
    async def publish(self, event_id, alert: bool = False):
        try:
            publish = self.misp.publish(event_id, alert)
            return publish
        except Exception as e:
            logger.error_log("MispPublishManagerModules", "publish", None, f"Unexpected error : {str(e)}")
            return
        
    async def unpublish(self, event_id):
        try:
            publish = self.misp.unpublish(event_id)
            return publish
        except Exception as e:
            logger.error_log("MispPublishManagerModules", "unpublish", None, f"Unexpected error : {str(e)}")
            return
        
class MispEventModules:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)

        self.event = MISPEvent()
        self.tehran_tz = ZoneInfo('Asia/Tehran')
        self.utc_now = datetime.now(tz=self.tehran_tz).timestamp()
        self.today = datetime.now().strftime("%Y-%m-%d")

    async def general_stats(self):
        try:
            return await asyncio.to_thread(self.misp.users_statistics)
        except Exception as e:
            logger.error_log("MispEventModules", "general_stats", None, f"Unexpected error : {str(e)}")
            return

    async def add_event(self, info: str, analysis: int, threat_level_id: int):
        event = {
            'info': info,
            'analysis': analysis,
            'threat_level_id': threat_level_id,
            'date': self.today,
            'timestamp': self.utc_now,
            'publish_timestamp': self.utc_now
        }
        try:
            created_event = await asyncio.to_thread(self.misp.add_event, event, pythonify=True)
            return {"Message": "Event created on MISP", "Created": created_event}
        except Exception as e:
            logger.error_log("MispEventModules", "add_event", None, f"Unexpected error : {str(e)}")
            return

    async def update_event(self, event_id: int, info: str, analysis: int, threat_level_id: int):
        try:
            event = await asyncio.to_thread(self.misp.get_event, event_id, pythonify=True)

            if event:
                event.info = info
                event.analysis = analysis
                event.threat_level_id = threat_level_id
                event.date = self.today
                event.timestamp = self.utc_now
                event.publish_timestamp = self.utc_now

                updated_event = await asyncio.to_thread(self.misp.update_event, event, pythonify=True)
                return {"Message": "Event updated on MISP", "update": updated_event}
            else:
                logger.error_log("MispEventModules", "update_event", None, f"Event with ID {event_id} not found.")
                return {"Error": f"Event with ID {event_id} not found." }

        except Exception as e:
            logger.error_log("MispEventModules", "update_event", None, f"Unexpected error : {str(e)}")
            return

    async def delete_event(self, event_id: int):
        try:
            report = await asyncio.to_thread(self.misp.delete_event, event_id)
            return report
        except Exception as e:
            logger.error_log("MispEventModules", "delete_event", None, f"Unexpected error : {str(e)}")
            return
        
    async def get_event(self, event_id):
        try:
            pprint(self.event)
            report = self.misp.get_event(
                event=event_id,
                deleted=False,
                extended=False,
                pythonify=False
            )
            return report
        except Exception as e:
            logger.error_log("MispEventModules", "delete_event", None, f"Unexpected error : {str(e)}")
            return
    async def events_list(self):
        try:
            events = self.misp.events(pythonify=False)
            return events
        
        except Exception as e:
            logger.error_log("MispEventModules", "events_list", None, f"Unexpected error : {str(e)}")
            return
        
class MispAttibutesModules:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)

        self.event = MISPEvent()
        self.attr = MISPAttribute()
        self.tehran_tz = ZoneInfo('Asia/Tehran')
        self.utc_now = datetime.now(tz=self.tehran_tz).timestamp()
        self.today = datetime.now().strftime("%Y-%m-%d")
    
    async def attributes_list(self):
        try:
            attr = self.misp.attributes(pythonify=False)
            return attr
        except Exception as e:
            logger.error_log("MispEventModules", "events_list", None, f"Unexpected error : {str(e)}")
            return

    async def add_attr(self, event_id, value, category, type_val, first_seen, last_seen, disable_correlation=False):
        try:
            first_seen_ts = int(datetime.strptime(first_seen, "%Y-%m-%d").timestamp())
            last_seen_ts = int(datetime.strptime(last_seen, "%Y-%m-%d").timestamp())
            timestamp_ts = int(datetime.now().timestamp()) 

            attribute = self.attr
            attribute.from_dict(
                value=value,
                category=category,
                type=type_val,
                timestamp=timestamp_ts,
                first_seen=first_seen_ts,
                last_seen=last_seen_ts,
                disable_correlation=disable_correlation
            )

            attr = self.misp.add_attribute(
                event=event_id,
                attribute=attribute,
                pythonify=True,
                break_on_duplicate=True
            )
            return attr
        except Exception as e:
            logger.error_log("MispEventModules", "add_attr", None, f"Unexpected error : {str(e)}")
            return

    async def update_attribute(self, attribute_id, value, category, type_val, first_seen, last_seen, disable_correlation=False):
        try:
            first_seen_ts = int(datetime.strptime(first_seen, "%Y-%m-%d").timestamp())
            last_seen_ts = int(datetime.strptime(last_seen, "%Y-%m-%d").timestamp())
            timestamp_ts = int(datetime.now().timestamp()) 

            attribute = self.attr
            attribute.from_dict(
                value=value,
                category=category,
                type=type_val,
                timestamp=timestamp_ts,
                first_seen=first_seen_ts,
                last_seen=last_seen_ts,
                disable_correlation=disable_correlation
            )

            attr = self.misp.update_attribute(
                attribute=attribute,
                attribute_id=attribute_id,
                pythonify=True,
            )
            return attr
        except Exception as e:
            logger.error_log("MispEventModules", "update_attr", None, f"Unexpected error : {str(e)}")
            return
        
    async def delete_attribute(self, attribute_id):
        try:
            deleted_obj = self.misp.delete_attribute(attribute=attribute_id, hard= False)
            return deleted_obj
        except Exception as e:
            logger.error_log("MispEventModules", "delete_attr", None, f"Unexpected error : {str(e)}")

    async def get_attribute(self, attribute_id):
        try:
            obj = self.misp.get_attribute(attribute=attribute_id, pythonify=False)
            return obj
        except Exception as e:
            logger("MispAttibutesModules", "get_attribute", None, f"Unexpected error : {str(e)}")
            return

class MISPSearchModles:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)

    async def search_misp(self, controller: str, kwargs: None):
        """
        Perform a flexible search in MISP with optional parameters.

        :param controller: One of 'events', 'attributes', or 'objects'.
        :param kwargs: Optional search filters (e.g. type_attribute, category, tags, etc.).
        :return: Search result from MISP, or None if an error occurs.
        """
        if controller not in ['events', 'attributes', 'objects']:
            raise ValueError("Controller must be one of: 'events', 'attributes', 'objects'.")

        if kwargs is None:
            kwargs = {}

        try:
            result = self.misp.search(controller=controller, **kwargs)
            return result
        except Exception as e:
            logger.error(f"Search failed: {str(e)}")
            return None

class MispEventReportModules:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)
        
    async def get_event_reports(self, report_id):
        try:
            obj = self.misp.get_event_reports(report_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispEventReportModules", "get_event_reports", None, f"Unexpected error : {str(e)}")
            return

    async def get_event_reports(self, report_id):
        try:
            obj = self.misp.get_event_reports(report_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispEventReportModules", "get_event_report", None, f"Unexpected error : {str(e)}")
            return

    async def update_event_report(self, report_data, report_id):
        try:
            obj = self.misp.update_event_report(report_data, report_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispEventReportModules", "update_event_report", None, f"Unexpected error : {str(e)}")
            return
        
    async def delete_event_report(self, report_id):
        try:
            obj = self.misp.delete_event_report(report_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispEventReportModules", "delete_event_report", None, f"Unexpected error : {str(e)}")
            return

class MispTagsModules:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)
        
    async def add_tag(self, tag_report):
        try:
            obj = self.misp.add_tag(tag_report, pythonify=False)
            return obj
        except Exception as e:
            logger.error_log("MispTagsModules", "add_tag", None, f"Unexpected error : {str(e)}")
            return
        
    async def update_tag(self, tag_report, tags_id):
        try:
            obj = self.misp.update_tag(tag_report, tags_id, pythonify=False)
            return obj
        except Exception as e:
            logger.error_log("MispTagsModules", "update_tag", None, f"Unexpected error : {str(e)}")
            return
        
    async def delete_tag(self, tag_id):
        try:
            obj = self.misp.delete_tag(tag_id)
            return obj
        except Exception as e:
            logger.error_log("MispTagsModules", "delete_tag", None, f"Unexpected error : {str(e)}")
            return
        
    async def list_tag(self):
        try:
            obj = self.misp.tags(False)
            return obj
        except Exception as e:
            logger.error_log("MispTagsModules", "list_tag", None, f"Unexpected error : {str(e)}")
            return
        
    async def get_tag(self, tag_id):
        try:
            obj = self.misp.get_tag(tag_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispTagsModules", "get_tag", None, f"Unexpected error : {str(e)}")
            return
        
class MispObjectsModules:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)
        
    async def add_obj(self, event_id, misp_object):
        try:
            obj = self.misp.add_object(event_id, misp_object, False, False)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "add_obj", None, f"Unexpected error : {str(e)}")
            return
        
    async def update_obj(self, obj_id, misp_object):
        try:
            obj = self.misp.update_object(misp_object, obj_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "update_obj", None, f"Unexpected error : {str(e)}")
            return

    async def get_obj(self, obj_id):
        try:
            obj = self.misp.get_object(obj_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "get_obj", None, f"Unexpected error : {str(e)}")
            return
        
    async def delete_obj(self, obj_id):
        try:
            obj = self.misp.delete_object(obj_id)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "delete_obj", None, f"Unexpected error : {str(e)}")
            return
        
class MispFeedsModules:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)
        
    async def add_feed(self, feed_obj):
        try:
            obj = self.misp.add_feed(feed_obj, False)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "add_feed", None, f"Unexpected error : {str(e)}")
            return
        
    async def update_feed(self, feed_id, feed_obj):
        try:
            obj = self.misp.update_feed(feed_obj, feed_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "update_feed", None, f"Unexpected error : {str(e)}")
            return

    async def get_feed(self, feed_id):
        try:
            obj = self.misp.get_feed(feed_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "get_feed", None, f"Unexpected error : {str(e)}")
            return

    async def feeds(self):
        try:
            obj = self.misp.feeds( False)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "feeds", None, f"Unexpected error : {str(e)}")
            return      
        
        
    async def delete_feed(self, feed_id):
        try:
            obj = self.misp.delete_feed(feed_id)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "delete_feed", None, f"Unexpected error : {str(e)}")
            return
 
class MispAttributeProposalsModules:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)
        
    async def attribute_proposals(self):
        try:
            obj = self.misp.attribute_proposals( False)
            return obj
        except Exception as e:
            logger.error_log("MispAttributeProposalsModules", "attribute_proposals", None, f"Unexpected error : {str(e)}")
            return       
    
    async def get_attribute_proposal(self, attr_prp_id):
        try:
            obj = self.misp.get_attribute_proposal(attr_prp_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispAttributeProposalsModules", "get_attribute_proposal", None, f"Unexpected error : {str(e)}")
            return

    async def add_attribute_proposal(self, event_id, attr_prp_obj):
        try:
            obj = self.misp.add_attribute_proposal(event_id, attr_prp_obj, False)
            return obj
        except Exception as e:
            logger.error_log("MispAttributeProposalsModules", "add_attribute_proposal", None, f"Unexpected error : {str(e)}")
            return
    
    async def update_attribute_proposal(self, attr_prp_id, attr_prp_obj):
        try:
            obj = self.misp.update_attribute_proposal(attr_prp_id, attr_prp_obj, False)
            return obj
        except Exception as e:
            logger.error_log("MispAttributeProposalsModules", "update_attribute_proposal", None, f"Unexpected error : {str(e)}")
            return
        
    async def delete_attribute_proposal(self, attr_prp_id):
        try:
            obj = self.misp.delete_attribute_proposal(attr_prp_id)
            return obj
        except Exception as e:
            logger.error_log("MispAttributeProposalsModules", "delete_attribute_proposal", None, f"Unexpected error : {str(e)}")
            return    
        
class MispUserManagementModules:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)
        
    async def add_user(self, user_obj):
        try:
            obj = self.misp.add_user(user_obj, False)
            return obj
        except Exception as e:
            logger.error_log("MispUserManagementModules", "add_user", None, f"Unexpected error : {str(e)}")
            return 500
        
    async def update_user(self, user_id, user_obj):
        try:
            obj = self.misp.update_user(user_obj, user_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispUserManagementModules", "update_user", None, f"Unexpected error : {str(e)}")
            return 500

    async def get_user(self, user_id):
        try:
            obj = self.misp.get_user(user_id, False, False)
            return obj
        except Exception as e:
            logger.error_log("MispUserManagementModules", "get_user", None, f"Unexpected error : {str(e)}")
            return

    async def users(self, search: None, organisation: None):
        try:
            
            obj = self.misp.users(search, organisation, False)
            return obj
        except Exception as e:
            logger.error_log("MispUserManagementModules", "users", None, f"Unexpected error : {str(e)}")
            return      
        
        
    async def delete_user(self, user_id):
        try:
            obj = self.misp.delete_user(user_id)
            return obj
        except Exception as e:
            logger.error_log("MispUserManagementModules", "delete_user", None, f"Unexpected error : {str(e)}")
            return
 
        
