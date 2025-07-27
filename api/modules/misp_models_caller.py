import asyncio
from pymisp import PyMISP, MISPEvent, MISPAttribute
from django.conf import settings
from pprint import pprint
from datetime import datetime
from zoneinfo import ZoneInfo
from api.logs import LoggerService

logger = LoggerService


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

