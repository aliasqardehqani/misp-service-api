### MISP Integration with Django API

### This project includes a MISP (Malware Information Sharing Platform) service integrated into a Django-based API.
### The goal is to provide a simple and extensible interface for interacting with MISP through Django REST API endpoints.
### 
### Feel free to explore, contribute, or raise issues.
### Let’s collaborate to make cyber threat intelligence sharing easier and more efficient

```markdown
# 🔐 MISP API Integration with PyMISP in Sandbox/Gateway

This project implements **MISP (Malware Information Sharing Platform)** API endpoints using the powerful `PyMISP` Python module inside a custom service module located at:

```

/misp-service-api/api/modules/misp\_models\_caller.py

````

## 📌 Purpose

The goal is to interact with a MISP instance by:
- Creating events
- Searching events, attributes, and objects
- Extending a modular service-based architecture (e.g., Sandbox/Gateway)

---

## 📦 Installation

1. **Clone the Repository**
   ```bash
   git clone https://your-repo-url.git
   cd misp-service-api
````

2. **Install Requirements**

   ```bash
   pip install pymisp
   ```

3. **Add to `INSTALLED_APPS`** in `settings.py` (if using Django):

   ```python
   INSTALLED_APPS = [
       ...
       'rest_framework',
       'your_app_name',  # Replace with actual app
   ]
   ```

---

## ⚙️ Configuration

Add the following variables to your environment or settings:

```python
# settings.py or .env
MISP_URL = 'https://your-misp-instance.com'
MISP_KEY = 'your-misp-auth-key'
```

---

## 🧠 About MISP Events

In MISP, an **event** acts as a container for contextual data. Each event encapsulates threat intelligence indicators like IPs, domains, hashes, etc., allowing structured analysis and sharing.

---

## 🔧 Usage Examples

### 1. Add Event to MISP

```python
from pymisp import PyMISP, MISPEvent

class MispEventModules:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)
        self.today = "2025-07-27"
        self.utc_now = int(datetime.utcnow().timestamp())

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
```

---

### 2. Search in MISP

```python
class MISPSearchModles:
    def __init__(self):
        self.misp = PyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=False, debug=False)

    async def search_misp(self, controller: str, kwargs: dict = None):
        """
        Perform a flexible search in MISP with optional parameters.

        :param controller: One of 'events', 'attributes', or 'objects'.
        :param kwargs: Optional search filters (e.g. type_attribute, category, tags, etc.).
        :return: Search result from MISP, or None if an error occurs.
        """
        if controller not in ['events', 'attributes', 'objects']:
            raise ValueError("Controller must be one of: 'events', 'attributes', 'objects'.")

        try:
            result = self.misp.search(controller=controller, **(kwargs or {}))
            return result
        except Exception as e:
            logger.error(f"Search failed: {str(e)}")
            return None
```

---

## 📁 Folder Structure

```
misp-service-api/
└── api/
    └── modules/
        └── misp_models_caller.py   # Core logic for MISP interaction
```

---

## ✅ Status

* [x] Add Event
* [x] Search Events / Attributes / Objects
* [ ] Add Attribute (Coming soon)
* [ ] Delete Event (Coming soon)

---

## 🤝 License

MIT License. Free for personal or commercial use.

---

## 👤 Author

Developed by **Aliasqar**, a security enthusiast and backend developer.
Feel free to contribute or report issues!

