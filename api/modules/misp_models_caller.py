import asyncio
import uuid
from pymisp import *
from django.conf import settings
from pprint import pprint
from datetime import datetime
from zoneinfo import ZoneInfo
from api.logs import LoggerService

logger = LoggerService

class MispPublishManagerModules:
    '''Holds configuration for publishing a MISP event.'''
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)
    async def publish(self, event_id, alert: bool = False):
        '''
        Publishing event with eventID
        
        Args:
            event_id (int) : an id of event we want to publish
            alert (bool) : a notification send to all users atfer publishing
        '''
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
    '''Api`s to crud action for an event'''
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
        '''
        A new event is added, 3 fields are received by the user client with the API and the other fields are filled with code.
        
        Args:
            info (str): General information about the event.
            analysis (int):  1 -> initial, 2 -> onginig, 3 -> completed
            threat_level_id (int): ID representing the event's threat level. 1 -> High, 2 -> Medium, 3-> Low, 4-> Undefined

        '''
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
        '''
        Update an event by args 
        
        Args:
            event_id (int)
            info (str): General information about the event.
            analysis (int):  1 -> initial, 2 -> onginig, 3 -> completed
            threat_level_id (int): ID representing the event's threat level. 1 -> High, 2 -> Medium, 3-> Low, 4-> Undefined

        '''
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
        '''
        Delete an event by eventID
        
        Args:
            event_id (int)
        '''
        try:
            report = await asyncio.to_thread(self.misp.delete_event, event_id)
            return report
        except Exception as e:
            logger.error_log("MispEventModules", "delete_event", None, f"Unexpected error : {str(e)}")
            return
        
    async def get_event(self, event_id):
        '''
        Get an event by eventID
        
        Args:
            event_id (int)
        '''
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
    '''Attribute add to a event. '''
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
        """
        Add a new attribute to a MISP event. These fields are typically used in the client API body.

        Args:
            event_id (int): ID of the MISP event to which the attribute will be added.
            category (str): Attribute category. This must be a valid MISP category string.
                For more details on categories and allowed values, refer to:
                https://www.misp-project.org/datamodels/
                
            type (str): Type of the attribute (e.g., ip-src, domain, etc.).
            value (str): The value depends on your selection in the category and its type. 
                For example, if you select the Network activity category and the ip-src type, you should use the value 192.168.30.131.
                
            first_seen (str, optional): Posting time for Y-M-D format and.
            last_seen (str, optional): Posting time for Y-M-D format and.
            disable_correlation (bool, optional): Whether to disable correlation for this attribute.

        Returns:
            dict: Response from the MISP API after adding the attribute.
        """
        
        
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
        """
        Update a attribute. These fields are typically used in the client API body.

        Args:
            attribute_id (int): ID of the attribute .
            category (str): Attribute category. This must be a valid MISP category string.
                For more details on categories and allowed values, refer to:
                https://www.misp-project.org/datamodels/
                
            type (str): Type of the attribute (e.g., ip-src, domain, etc.).
            value (str): The value depends on your selection in the category and its type. 
                For example, if you select the Network activity category and the ip-src type, you should use the value 192.168.30.131.
                
            first_seen (str, optional): Posting time for Y-M-D format and.
            last_seen (str, optional): Posting time for Y-M-D format and.
            disable_correlation (bool, optional): Whether to disable correlation for this attribute.

        Returns:
            dict: Response from the MISP API after updating the attribute.
        """
        
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
        """
        Delete a attribute . These fields are typically used in the client API body.

        Args:
            attribute_id (int): ID of the attribute .
        """
        
        try:
            deleted_obj = self.misp.delete_attribute(attribute=attribute_id, hard= False)
            return deleted_obj
        except Exception as e:
            logger.error_log("MispEventModules", "delete_attr", None, f"Unexpected error : {str(e)}")

    async def get_attribute(self, attribute_id):
        """
        Get a attribute information with an ID . These fields are typically used in the client API body.

        Args:
            attribute_id (int): ID of the attribute .
        """
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

        Args:
            controller: One of 'events', 'attributes', or 'objects'.
            kwargs: Optional search filters (e.g. type_attribute, category, tags, etc.).
            
        Returns: 
            dict: Search result from MISP, or None if an error occurs.
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
        """
        Get a report information to a ReportID.

        Args:
            report_id (int): ID of the report.
        """
        try:
            obj = self.misp.get_event_reports(report_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispEventReportModules", "get_event_reports", None, f"Unexpected error : {str(e)}")
            return

    async def add_event_report(self, event_id, report_data):
        """
        Add a report to a MISP event.

        Args:
            event_id (int): ID of the MISP event to which the report will be attached.
            report_data (dict): Dictionary containing report details:
                - name (str): Title or name of the report.
                - content (str): The full text or body of the report.
                - timestamp (str): Time the report was created (in ISO 8601 format or UNIX timestamp).
                - deleted (bool): Whether the report is marked as deleted.

        Returns:
            dict: Response from the MISP API after adding the report.
        """
        
        try:
            obj = self.misp.add_event_report(event_id, report_data, False)
            
            return obj
        except Exception as e:
            logger.error_log("MispEventReportModules", "update_event_report", None, f"Unexpected error : {str(e)}")
            return
    
    async def update_event_report(self, report_data, report_id):
        """
        Update a report to a ReportID.

        Args:
            report_id (int): ID of the report.
            report_data (dict): Dictionary containing report details:
                - name (str): Title or name of the report.
                - content (str): The full text or body of the report.
                - timestamp (str): Time the report was created (in ISO 8601 format or UNIX timestamp).
                - deleted (bool): Whether the report is marked as deleted.

        Returns:
            dict: Response from the MISP API after updating the report.
        """
        
        try:
            obj = self.misp.update_event_report(report_data, report_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispEventReportModules", "update_event_report", None, f"Unexpected error : {str(e)}")
            return
        
    async def delete_event_report(self, report_id):
        """
        Delete a report to a ReportID.

        Args:
            report_id (int): ID of the report.
        """
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
        """
        Add a tag to the MISP instance.

        Args:
            tag_data (dict): Dictionary containing tag details:
                - name (str): Name of the tag (e.g., "tlp:red" or "My-Tag-1").
                - colour (str): Hex color code for the tag (e.g., "#FF0000").
                - relationship_type (str or None): Optional relationship type if the tag is used in a galaxy/cluster relationship.
                - local (bool): Whether the tag is local to the instance.

        Returns:
            dict: Response from the MISP API after adding the tag.
        """ 
        try:
            obj = self.misp.add_tag(tag_report, pythonify=False)
            return obj
        except Exception as e:
            logger.error_log("MispTagsModules", "add_tag", None, f"Unexpected error : {str(e)}")
            return
        
    async def update_tag(self, tag_report, tags_id):
        """
        Update a tag to the MISP instance.

        Args:
            tags_id (int) : Tag id we want to update .
            tag_report (dict): Dictionary containing tag details:
                - name (str): Name of the tag (e.g., "tlp:red" or "My-Tag-1").
                - colour (str): Hex color code for the tag (e.g., "#FF0000").
                - relationship_type (str or None): Optional relationship type if the tag is used in a galaxy/cluster relationship.
                - local (bool): Whether the tag is local to the instance.

        Returns:
            dict: Response from the MISP API after updating the tag.
        """ 
        try:
            obj = self.misp.update_tag(tag_report, tags_id, pythonify=False)
            return obj
        except Exception as e:
            logger.error_log("MispTagsModules", "update_tag", None, f"Unexpected error : {str(e)}")
            return
        
    async def delete_tag(self, tag_id):
        """
        Delete a tag with ID.

        Args:
            tags_id (int) : Tag id we want to  delete .
            
        """
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
        """
        Get info a tag with ID.

        Args:
            tags_id (int) : Tag id we want to  get info .
            
        """
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
        """
        Add a MISP object to a specific event.

        Args:
            event_id (int): ID of the MISP event to which the object will be added.
            misp_object (dict): Dictionary containing object details. Must follow the MISP object format.
                Required fields:
                    - name (str): Name of the object template (e.g., "domain-ip").
                    - meta-category (str): Meta category of the object (e.g., "network").
                    - description (str): Human-readable description of the object.
                    - template_uuid (str): UUID of the object template used.
                    - template_version (int): Version of the template used.
                    - uuid (str): UUID assigned to this object (can be generated by client).
                    - timestamp (int): Time of creation (UNIX timestamp).
                    - comment (str): Optional comment or notes about the object.
                    - first_seen (int): Timestamp when the object was first observed.
                    - last_seen (int): Timestamp when the object was last observed.
                    - deleted (bool): Whether the object is marked as deleted.
                    - attributes (list): List of attribute dictionaries, each with:
                        - object_relation (str): The relation name (e.g., "domain", "ip").
                        - value (str): The value for that attribute (e.g., "example.com").

        Returns:
            dict: API response from the MISP server after adding the object.
        """

        try:
            obj = self.misp.add_object(event_id, misp_object, False, False)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "add_obj", None, f"Unexpected error : {str(e)}")
            return
        
    async def update_obj(self, obj_id, misp_object):
        """
        Update a MISP object to a specific event.

        Args:
            event_id (int): ID of the MISP event to which the object will be added.
            misp_object (dict): Dictionary containing object details. Must follow the MISP object format.
                Required fields:
                    - name (str): Name of the object template (e.g., "domain-ip").
                    - meta-category (str): Meta category of the object (e.g., "network").
                    - description (str): Human-readable description of the object.
                    - template_uuid (str): UUID of the object template used.
                    - template_version (int): Version of the template used.
                    - uuid (str): UUID assigned to this object (can be generated by client).
                    - timestamp (int): Time of creation (UNIX timestamp).
                    - comment (str): Optional comment or notes about the object.
                    - first_seen (int): Timestamp when the object was first observed.
                    - last_seen (int): Timestamp when the object was last observed.
                    - deleted (bool): Whether the object is marked as deleted.
                    - attributes (list): List of attribute dictionaries, each with:
                        - object_relation (str): The relation name (e.g., "domain", "ip").
                        - value (str): The value for that attribute (e.g., "example.com").

        Returns:
            dict: API response from the MISP server after updating the object.
        """
        try:
            obj = self.misp.update_object(misp_object, obj_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "update_obj", None, f"Unexpected error : {str(e)}")
            return

    async def get_obj(self, obj_id):
        """
        Get a objects with object id.

        Args:
            obj_id (int): ID of the Object.
        """
        try:
            obj = self.misp.get_object(obj_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "get_obj", None, f"Unexpected error : {str(e)}")
            return
        
    async def delete_obj(self, obj_id):
        """
        Delete a objects with object id.

        Args:
            obj_id (int): ID of the Object.
        """
        
        
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
        """
        Add a feed to the MISP instance.

        Args:
            feed_obj (dict): Dictionary containing feed configuration details:
                - name (str): Name for the new feed.
                - provider (str): Name of the provider service (e.g., "MISP").
                - url (str): URL of the feed to be added to the MISP instance.
                - enabled (bool): Whether the feed is enabled.
                - distribution (int): Distribution level:
                    1 -> Your organisation only  
                    2 -> This community only  
                    3 -> Connected communities  
                    4 -> All communities  
                    5 -> Inherit from feed
                - settings (str): JSON string with additional feed settings.

        Returns:
            dict: API response from the MISP server after adding the feed.
        """
        
        try:
            obj = self.misp.add_feed(feed_obj, False)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "add_feed", None, f"Unexpected error : {str(e)}")
            return
        
    async def update_feed(self, feed_id, feed_obj):
        """
        Update a feed .

        Args:
            feed_id (int) : Feed id to update
            feed_obj (dict): Dictionary containing feed configuration details:
                - name (str): Name for the new feed.
                - provider (str): Name of the provider service (e.g., "MISP").
                - url (str): URL of the feed to be added to the MISP instance.
                - enabled (bool): Whether the feed is enabled.
                - distribution (int): Distribution level:
                    1 -> Your organisation only  
                    2 -> This community only  
                    3 -> Connected communities  
                    4 -> All communities  
                    5 -> Inherit from feed
                - settings (str): JSON string with additional feed settings.

        Returns:
            dict: API response from the MISP server after updating the feed.
        """
        
        
        try:
            obj = self.misp.update_feed(feed_obj, feed_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "update_feed", None, f"Unexpected error : {str(e)}")
            return

    async def get_feed(self, feed_id):
        """
        Get a feed .

        Args:
            feed_id (int) : Feed id to get info .
        """        
        try:
            obj = self.misp.get_feed(feed_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "get_feed", None, f"Unexpected error : {str(e)}")
            return

    async def feeds(self):
        """ Feeds list"""
        try:
            obj = self.misp.feeds( False)
            return obj
        except Exception as e:
            logger.error_log("MispObjectsModules", "feeds", None, f"Unexpected error : {str(e)}")
            return      
            
    async def delete_feed(self, feed_id):
        """
        Delete a feed .

        Args:
            feed_id (int) : Feed id to delete .
        """  
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
        """Proposals all list ."""
        try:
            obj = self.misp.attribute_proposals( False)
            return obj
        except Exception as e:
            logger.error_log("MispAttributeProposalsModules", "attribute_proposals", None, f"Unexpected error : {str(e)}")
            return       
    
    async def get_attribute_proposal(self, attr_prp_id):
        """
        Get a Propose .

        Args:
            attr_prp_id (int): ID of the attribute proposal.
            """
        try:
            obj = self.misp.get_attribute_proposal(attr_prp_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispAttributeProposalsModules", "get_attribute_proposal", None, f"Unexpected error : {str(e)}")
            return

    async def add_attribute_proposal(self, event_id, attr_prp_obj):
        """
        Propose a new attribute for a specific MISP event (as a shadow attribute).

        Args:
            event_id (int): ID of the MISP event where the attribute proposal will be added.
            attr_prp_obj (dict): Dictionary containing the proposed attribute details:
                - value (str): The value of the proposed attribute (e.g., "8.8.8.8").
                - type (str): MISP attribute type (e.g., "ip-src", "domain", "hash", etc.).
                - category (str): Category under which this attribute falls (e.g., "Network activity").
                - to_ids (bool): Whether this attribute should be used for detection.
                - comment (str): Optional comment explaining the proposal.

        Returns:
            dict: Response from the MISP API after submitting the attribute proposal.
        """
        
        
        try:
            obj = self.misp.add_attribute_proposal(event_id, attr_prp_obj, False)
            return obj
        except Exception as e:
            logger.error_log("MispAttributeProposalsModules", "add_attribute_proposal", None, f"Unexpected error : {str(e)}")
            return
    
    async def update_attribute_proposal(self, attr_prp_id, attr_prp_obj):
        """
        Update an existing attribute proposal in a MISP event.

        Args:
            attr_prp_id (int): ID of the attribute proposal (shadow attribute) to update.
            attr_prp_obj (dict): Dictionary containing updated attribute fields:
                - value (str): The new proposed value (e.g., "1.1.1.1").
                - type (str): MISP attribute type (e.g., "ip-dst", "domain", etc.).
                - category (str): Category of the attribute (e.g., "Network activity").
                - to_ids (bool): Whether this attribute should be used for detection.
                - comment (str): Optional comment or reasoning for the proposal.

        Returns:
            dict: API response from the MISP server after updating the attribute proposal.
        """
        
        try:
            obj = self.misp.update_attribute_proposal(attr_prp_id, attr_prp_obj, False)
            return obj
        except Exception as e:
            logger.error_log("MispAttributeProposalsModules", "update_attribute_proposal", None, f"Unexpected error : {str(e)}")
            return
        
    async def delete_attribute_proposal(self, attr_prp_id):
        """
        Delete a Propose.

        Args:
            attr_prp_id (int): ID of the attribute proposal .
            """
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
        """
        Add a new user to the MISP instance.

        Args:
            user_obj (dict): Dictionary containing a single key "User" with user details:
                - email (str): Email address of the new user.
                - password (str): Password for the new user account.
                - org_id (int): ID of the organization the user belongs to.
                - role_id (int): ID of the role assigned to the user 
                                 (e.g., 1 = Site Admin, 2 = Org Admin, 3 = User, etc.).
        Returns:
            dict: Response from the MISP API after creating the user.
        """
        
        try:
            obj = self.misp.add_user(user_obj, False)
            return obj
        except Exception as e:
            logger.error_log("MispUserManagementModules", "add_user", None, f"Unexpected error : {str(e)}")
            return 500
        
    async def update_user(self, user_id, user_obj):
        """
        Update a new user to the MISP instance.

        Args:
            user_id (int) : Id of user to update .
            user_obj (dict): Dictionary containing a single key "User" with user details:
                - email (str): Email address of the new user.
                - password (str): Password for the new user account.
        """
        try:
            obj = self.misp.update_user(user_obj, user_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispUserManagementModules", "update_user", None, f"Unexpected error : {str(e)}")
            return 500

    async def get_user(self, user_id):
        """
        Get a user to the MISP instance.

        Args:
            user_id (int) : Id of user to get info .
        """
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
        """
        delete a user .

        Args:
            user_id (int) : Id of user .
        """
        try:
            obj = self.misp.delete_user(user_id)
            return obj
        except Exception as e:
            logger.error_log("MispUserManagementModules", "delete_user", None, f"Unexpected error : {str(e)}")
            return
 
class MispOrganisationModules:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)
        
    async def add_orgns(self, orgns_obj):
        """
        Add an organisation to MISP, typically used to organize private events or separate data visibility.

        Args:
            Organisation (dict): Dictionary containing organisation details:
                - name (str): Name of the organisation (required).
                - type (str): Type of organisation (e.g., "ADMIN", "User").
                - nationality (str): Nationality or country name.
                - description (str): Optional description of the organisation.
                - created_by (str): The creator of the organisation (can be a username or system ID).
                - local (bool): Whether the organisation is local to this MISP instance.

        Returns:
            dict: Response from the MISP API after adding the organisation.
        """
        try:
            obj = self.misp.add_organisation(orgns_obj, False)
            return obj
        except Exception as e:
            logger.error_log("MispOrganisationModules", "add_orgns", None, f"Unexpected error : {str(e)}")
            return 500
        
    async def update_orgns(self, orgns_id, orgns_obj):
        """
        update an organisation .
        
        Args:
            orgns_id (int): Orgns id to get orgns object .
            Organisation (dict) : Every field can to be null or remove when you want to  updating .
                - name (str): Name of the organisation (required).
                - type (str): Type of organisation (e.g., "ADMIN", "User").
                - nationality (str): Nationality or country name.
                - description (str): Optional description of the organisation.
                - created_by (str): The creator of the organisation (can be a username or system ID).
                - local (bool): Whether the organisation is local to this MISP instance.

        """
        
        try:
            obj = self.misp.update_organisation(orgns_obj, orgns_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispOrganisationModules", "update_orgns", None, f"Unexpected error : {str(e)}")
            return 500

    async def get_orgns(self, orgns_obj):
        """
        Get an organisation .

        Args:
            orgns_id (int): Orgns id to get orgns object .
        """
        try:
            obj = self.misp.get_organisation(orgns_obj, False)
            return obj
        except Exception as e:
            logger.error_log("MispOrganisationModules", "get_orgns", None, f"Unexpected error : {str(e)}")
            return

    async def organisations(self, scope: str = "local", search: str = None):
        try:
            obj = self.misp.organisations(scope, search, False)
            return obj
        except Exception as e:
            logger.error_log("MispOrganisationModules", "organisations", None, f"Unexpected error : {str(e)}")
            return      
          
    async def delete_orgns(self, orgns_id):
        """
        Update an organisation .
        
        Args:
            orgns_id (int): Orgns id to get orgns object .
        """
        try:
            obj = self.misp.delete_organisation(orgns_id)
            return obj
        except Exception as e:
            logger.error_log("MispOrganisationModules", "delete_orgns", None, f"Unexpected error : {str(e)}")
            return
        
class MispNoteModules:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)
        

    async def add_note(self, note_data: dict):
        """
        Add a note (analyst comment) to a specific MISP object (e.g., Event or Attribute).

        Args:
            note_data (dict): Dictionary with a single "Note" key containing note details:
                - note (str): The textual content of the note.
                - language (str): Language code of the note (e.g., "en", "de"). Can be empty.
                - object_uuid (str): UUID of the MISP object the note is related to (e.g., an Event or Attribute).
                - object_type (str): Type of object being referenced ("Event", "Attribute", etc.).
                - analyst_data_object_type (str or None): Optional type hint for MISP processing. Used in specific cases.

        Returns:
            dict: API response from MISP after submitting the note.
        """

        
        
        try:
            note_obj = MISPNote()
            note_obj.from_dict(**note_data)
            obj = self.misp.add_note(note_obj, False)
            return obj
        except Exception as e:
            logger.error_log("MispNoteModules", "add_note", None, f"Unexpected error : {str(e)}")
            return 500
        
    async def update_note(self, note_id, note_data: dict):
        """
        Update Note objects .

        Args:
            note_data (dict): Dictionary with a single "Note" key containing note details:
                - note (str): The textual content of the note.
                - language (str): Language code of the note (e.g., "en", "de"). Can be empty.
                - object_uuid (str): UUID of the MISP object the note is related to (e.g., an Event or Attribute).
                - object_type (str): Type of object being referenced ("Event", "Attribute", etc.).
                - analyst_data_object_type (str or None): Optional type hint for MISP processing. Used in specific cases.

        Returns:
            dict: API response from MISP after updating the note.
        """
        
        try:
            note_obj = MISPNote()
            note_obj.from_dict(**note_data)
            obj = self.misp.update_note(note_obj, note_id, False)
            return obj
        except Exception as e:
            logger.error_log("MispOrganisationModules", "update_note", None, f"Unexpected error : {str(e)}")
            return 500

    async def get_note(self, note_uuid):
        """
        Get Note informations .

        Args:
            note_uuid (str) : Get note need to get uuid4 .
        """
        try:
            obj = self.misp.get_note(note_uuid, False)
            return obj
        except Exception as e:
            logger.error_log("MispNoteModules", "get_note", None, f"Unexpected error : {str(e)}")
            return
        
class MispAddAnalystDataModules:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)
        

    async def add_analyst_data(self, analyst_data: dict):
        """
        Add analyst data to a MISP object. Supports notes, opinions, and relationships.
        First, it must be converted to a standard dict using the formdict method, then sent to the desired function.
        
        
        Args:
            analyst_data (dict): A dictionary with a "method" key and a corresponding payload:
                - method (str): Type of analyst data. Must be one of:
                    "note", "opinion", "relationship".

                If method == "note":
                    Note (dict): 
                        - note (str): Text of the note.
                        - language (str): Language code (e.g., "en"). Optional.
                        - object_uuid (str): UUID of the object to attach the note to.
                        - object_type (str): Type of the object (e.g., "Event", "Attribute").
                        - analyst_data_object_type (str or None): Optional.

                If method == "opinion":
                    Opinion (dict): 
                        - object_uuid (str): UUID of the object to attach the opinion to.
                        - object_type (str): Type of the object.
                        - opinion (int): Analyst rating (0–100).
                        - comment (str): Analyst's comment.

                If method == "relationship":
                    Relationship (dict):
                        - object_uuid (str): UUID of the source object.
                        - object_type (str): Type of the source object.
            {
    "method": "note",
    "id": 4,
    "Note": {
        "note": "Here is new edqfwegfewgwbwfgrg3e",
        "language": "",
        "object_uuid": "05b9cde9-3c5e-4737-8dac-1aab4e3be386", //uuid is the attribute we need to add to the note
        "object_type": "Event",
        "analyst_data_object_type": null // Used in important places.
    }            - related_object_uuid (str): UUID of the target object.
                        - related_object_type (str): Type of the related object.
                        - relationship_type (str): Type of relationship (e.g., "corroborates", "derived-from").

        Returns:
            dict: API response from MISP after submitting the analyst data.
        """

        
        try:
            method = analyst_data.get("method")
            if "note" == method:
                dt_obj = MISPNote()
                dt_obj.from_dict(**analyst_data)
                obj = self.misp.add_analyst_data(dt_obj, False)
                return obj
            elif "opinion" == method:
                dt_obj = MISPOpinion()
                dt_obj.from_dict(**analyst_data)
                obj = self.misp.add_analyst_data(dt_obj, False)
                return obj
            elif "relationship" == method:
                dt_obj = MISPRelationship()
                dt_obj.from_dict(**analyst_data)
                obj = self.misp.add_analyst_data(dt_obj, False)
                return obj
            else:
                logger.error_log("MispAddAnalystDataModules", "add_analyst_data", None, f"Unexpected error : your request method not found")
                return 500
        except Exception as e:
            logger.error_log("MispAddAnalystDataModules", "add_analyst_data", None, f"Unexpected error : {str(e)}")
            return 500
        
    async def update_analyst_data(self, analyst_data: dict):
        """
        Update an existing analyst data object (note, opinion, or relationship) in MISP.

        Args:
            analyst_data (dict): A dictionary containing the update request.
                - method (str): Type of analyst data. Must be one of:
                    "note", "opinion", or "relationship".
                    
                - id (int): ID of the analyst data object to update.

                Depending on the method, one of the following keys must also be present:

                If method == "note":
                    Note (dict): 
                        - note (str): Updated text of the note.
                        - language (str): Language code (e.g., "en"). Optional.
                        - object_uuid (str): UUID of the object the note is attached to.
                        - object_type (str): Type of the object (e.g., "Event", "Attribute").
                        - analyst_data_object_type (str or None): Optional.

                If method == "opinion":
                    Opinion (dict): 
                        - object_uuid (str): UUID of the object.
                        - object_type (str): Type of the object.
                        - opinion (int): Updated analyst rating (0–100).
                        - comment (str): Updated analyst comment.

                If method == "relationship":
                    Relationship (dict):
                        - object_uuid (str): UUID of the source object.
                        - object_type (str): Type of the source object.
                        - related_object_uuid (str): UUID of the target object.
                        - related_object_type (str): Type of the related object.
                        - relationship_type (str): Updated type of relationship.

        Returns:
            dict: Response from the MISP API after updating the analyst data.
        """        
        
        try:
            analyst_data_id = analyst_data.get("id")
            method = analyst_data.get("method")
            if "note" == method:
                dt_obj = MISPNote()
                dt_obj.from_dict(**analyst_data)
                obj = self.misp.update_analyst_data(dt_obj, analyst_data_id, False)
                return obj
            elif "opinion" == method:
                dt_obj = MISPOpinion()
                dt_obj.from_dict(**analyst_data)
                obj = self.misp.update_analyst_data(dt_obj, analyst_data_id, False)
                return obj
            elif "relationship" == method:
                dt_obj = MISPRelationship()
                dt_obj.from_dict(**analyst_data)
                obj = self.misp.update_analyst_data(dt_obj, analyst_data_id, False)
                return obj
            else:
                logger.error_log("MispAddAnalystDataModules", "update_analyst_data", None, f"Unexpected error : your request method not found")
                return 500
        except Exception as e:
            logger.error_log("MispAddAnalystDataModules", "update_analyst_data", None, f"Unexpected error : {str(e)}")
            return 500
        
    async def delete_analyst_data(self, analyst_data: dict):
        try:
            """
            Delete an existing analyst data object (note, opinion, or relationship) from MISP.

            Args:
                method (str): Type of analyst data to delete. Must be one of:
                    - "note"
                    - "opinion"
                    - "relationship"

                id (str): UUID or ID of the analyst data object to be deleted.

            Returns:
                dict: API response from MISP after deleting the analyst data.
            """
            
            
            analyst_data_id = analyst_data.get("id")
            method = analyst_data.get("method")
            if "note" == method:
                existing = self.misp.get_analyst_data(id, pythonify=True)
                print(existing)
                note = MISPNote()
                note.uuid = analyst_data_id
                obj = self.misp.delete_analyst_data(note)
                return obj  
            
            elif "opinion" == method:
                dt_obj = MISPOpinion()
                dt_obj.from_dict(**analyst_data)
                obj = self.misp.delete_analyst_data(dt_obj, analyst_data_id, False)
                return obj
            elif "relationship" == method:
                dt_obj = MISPRelationship()
                dt_obj.from_dict(**analyst_data)
                obj = self.misp.delete_analyst_data(dt_obj, analyst_data_id, False)
                return obj
            else:
                logger.error_log("MispAddAnalystDataModules", "delete_analyst_data", None, f"Unexpected error : your request method not found")
                return 500
        except Exception as e:
            logger.error_log("MispAddAnalystDataModules", "delete_analyst_data", None, f"Unexpected error : {str(e)}")
            return 500
        
    async def get_analyst_data(self, analyst_data):
        """
        Retrieve a MISP event by its UUID.

        Args:
            uuid (str): The UUID of the MISP event to retrieve.
        """
        try:
            uuid = analyst_data.get("uuid")
            obj = self.misp.get_analyst_data(uuid, False)
            return obj
        except Exception as e:
            logger.error_log("MispAddAnalystDataModules", "get_analyst_data", None, f"Unexpected error : {str(e)}")
            return 500
        
class MispGalaxyModules:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)
        
    async def add_galaxy_cluster(self, galaxy_obj, galaxy_cluster_obj):
        """
        Add a Galaxy Cluster to a specific Galaxy in MISP.

        Args:
            galaxy_obj (str): UUID of the galaxy to which the cluster should be added.

            galaxy_cluster_obj (dict): A dictionary containing the cluster's information. Expected structure:
                value (str): The name of the cluster (e.g., threat actor group name).
                description (str): A short explanation of what this cluster represents.
                distribution (int): Access control level.
                    0 -> Your organisation only,
                    1 -> This community only,
                    2 -> Connected communities,
                    3 -> All communities,
                    4 -> Sharing group only,
                    5 -> Inherit from event
                authors (list[str]): List of author(s) contributing to this cluster.
                meta (dict): Additional metadata such as synonyms, country, or tags.

        Returns:
            dict: API response from MISP upon success or failure.
        """
        
        try:
            obj = self.misp.add_galaxy_cluster(galaxy_obj, galaxy_cluster_obj, False)
            return obj
        except Exception as e:
            logger.error_log("MispGalaxyModules", "add_galaxy_cluster", None, f"Unexpected error : {str(e)}")
            return 500
    
    async def update_galaxy_cluster(self, galaxy_cluster_obj):
        """
        Update an existing Galaxy Cluster in MISP.

        Args:
            galaxy_cluster_obj (dict): Dictionary containing the updated Galaxy Cluster fields.
                Required field:
                    - uuid (str): UUID of the Galaxy Cluster to be updated.
                Optional fields:
                    - value (str): New name for the cluster.
                    - description (str): Updated description.
                    - distribution (int): New distribution level (0-5).
                    - authors (list[str]): List of updated authors.
                    - meta (dict): Updated metadata, such as:
                        - synonyms (list[str])
                        - country (list[str])
                        - cfr-type-of-incident (list[str])
        """
        try:
            obj = self.misp.update_galaxy_cluster(galaxy_cluster_obj, False)
            return obj
        except Exception as e:
            logger.error_log("MispGalaxyModules", "update_galaxy_cluster", None, f"Unexpected error : {str(e)}")
            return 500
        
    async def get_galaxy_cluster(self, uuid):
        try:
            obj = self.misp.get_galaxy_cluster(uuid, False)
            return obj
        except Exception as e:
            logger.error_log("MispGalaxyModules", "get_galaxy_cluster", None, f"Unexpected error : {str(e)}")
            return 500
        
    async def galaxies(self):
        try:
            obj = self.misp.galaxies(False, False)
            return obj
        except Exception as e:
            logger.error_log("MispGalaxyModules", "galaxies", None, f"Unexpected error : {str(e)}")
            return 500

    async def get_galaxy(self, gx_data):
        """
        Get a galaxy info by uuid
        
        Args:
            uuid (str) : UUID4  id from a galaxy objects.
        """
        try:
            uuid = gx_data.get('uuid')
            obj = self.misp.get_galaxy(uuid)
            return obj
        except Exception as e:
            logger.error_log("MispGalaxyModules", "get_galaxy", None, f"Unexpected error : {str(e)}")
            return 500

    async def publish_galaxy_cluster(self, uuid):
        """
        Publish a galaxy cluster by uuid
        
        Args:
            uuid (str) : UUID4  id from a galaxy cluster objects.
        """
        try:
            obj = self.misp.publish_galaxy_cluster(uuid)
            return obj
        except Exception as e:
            logger.error_log("MispGalaxyModules", "publish_galaxy_cluster", None, f"Unexpected error : {str(e)}")
            return 500

    async def delete_galaxy_cluster(self, uuid):
        """
        Delete a galaxy cluster by uuid
        
        Args:
            uuid (str) : UUID4  id from a galaxy cluster objects.
        """
        try:
            obj = self.misp.delete_galaxy_cluster(uuid, True)
            return obj
        except Exception as e:
            logger.error_log("MispGalaxyModules", "delete_galaxy_cluster", None, f"Unexpected error : {str(e)}")
            return 500

    async def search_galaxy(self, value):

        try:
            obj = self.misp.search_galaxy(value)
            return obj
        except Exception as e:
            logger.error_log("MispGalaxyModules", "search_galaxy", None, f"Unexpected error : {str(e)}")
            return 500
        
    async def search_galaxy_cluster(self, galaxy_id, context, searchall):
        """
        Search in galaxy by value from cluster .
        
        Args:
            galaxy_id () : Use uuid from a galaxy not galaxy cluster
            context () : The context must be one of all, default, custom, org, orgc, deleted
            searchall () :  Search field should to be from galaxy object 
          """
        try:
            obj = self.misp.search_galaxy_clusters(galaxy_id, context, searchall)
            return obj
        except Exception as e:
            logger.error_log("MispGalaxyModules", "search_galaxy_cluster", None, f"Unexpected error : {str(e)}")
            return 500
        
        
        