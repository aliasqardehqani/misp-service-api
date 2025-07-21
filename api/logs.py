# core/logging_service.py

import os
import json

from datetime import datetime
from zoneinfo import ZoneInfo

class LoggerService:
    """Handles structured and fail-safe logging to appropriate files."""

    BASE_DIR = "logs"

    MAX_LOG_SIZE_MB = 100
    
    @staticmethod
    def error_log(event_name: str, topic: str, message: str, error: str):
        """
        Logs error messages for a specific event.
        Clears the log file if it exceeds 100MB.
        Timestamps are recorded in Tehran local time.
        """
        tehran_time = datetime.now(ZoneInfo("Asia/Tehran"))

        log_text = (
            "\n==================== Log Error ===================================\n"
            f"Timestamp     : {tehran_time}\n"
            f"Event Name      : {event_name}\n"
            f"Topic/Queue   : {topic}\n"
            f"Failed Message: {message}\n"
            f"Error         : {error}\n"
            "====================================================================\n"
        )

        log_file_path = os.path.join(LoggerService.BASE_DIR, "error/error_log.log")

        try:
            os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

            if os.path.exists(log_file_path):
                file_size_mb = os.path.getsize(log_file_path) / (1024 * 1024)
                if file_size_mb > LoggerService.MAX_LOG_SIZE_MB:
                    with open(log_file_path, "w", encoding="utf-8") as log_file:
                        log_file.write("")

            with open(log_file_path, "a", encoding="utf-8") as log_file:
                log_file.write(log_text)

            return True
        except Exception as e:
            print(f"Error logging failed: {e}")
            return False