import asyncio
from pymisp import PyMISP, MISPEvent
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