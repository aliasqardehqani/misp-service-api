from pymisp import PyMISP, MISPEvent
from django.conf import settings
from pprint import pprint
from datetime import datetime
from zoneinfo import ZoneInfo

MISP_URL = 'https://192.168.30.131' 
MISP_KEY = 'EhzIj5MGkcYLzxrxpmAYZSdqkidTennNnPnQ1VnU'

# start connection to misp base model
# misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)

class MispModulesCaller:
    def __init__(self):
        """
        Misp class to call methods from PyMISP
        """
        self.misp = PyMISP(MISP_URL, MISP_KEY, ssl=False, debug=False)
        self.event = MISPEvent()
        self.tehran_tz = ZoneInfo('Asia/Tehran')
        self.utc_now = datetime.now(tz=self.tehran_tz).timestamp()
        self.today = datetime.now().strftime("%Y-%m-%d")

    def general_stats(self):
        resp = self.misp.users_statistics()
        return resp

    def add_event(self, info: str):
        self.event.info = info
        create_event = self.misp.add_event(self.event, pythonify=True)
        return create_event
    
    def update_event(self, 
                     event_id: int, 
                     info: str, 
                     analysis: int, 
                     threat_level_id: int):
        
        event = self.misp.get_event(event_id, pythonify=True)

        if event:
            event.info = info
            event.analysis = analysis
            event.threat_level_id = threat_level_id
            event.date = self.today
            event.timestamp = self.utc_now
            event.publish_timestamp = self.utc_now

            updated_event = self.misp.update_event(event, pythonify=True)
            pprint(updated_event)
        else:
            print("Event with ID 10 not found.")
    def delete_event(self, event_id):
        report = self.misp.delete_event(event_id)

        pprint(report)       
        
           
mi = MispModulesCaller()

# pprint(mi.add_event("AS TEST ON DJANGO"))
# pprint(mi.update_event(5, "Test in pehan", 1, 1))
# pprint(mi.delete_event(4))
