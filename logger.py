from kivy.logger import Logger as KivyLogger
from kivy.logger import FileHandler
from kivy.logger import file_log_handler
import time
import datetime

class TimeStampedFileHandler(FileHandler):
    def _write_message(self, record):
        # Add time to the record
        t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        m = str(record.msg)
        record.msg = str(t) + " " + m
        super()._write_message(record)

Logger = KivyLogger
Logger.removeHandler(file_log_handler)
file_log_handler = TimeStampedFileHandler()
Logger.addHandler(file_log_handler)