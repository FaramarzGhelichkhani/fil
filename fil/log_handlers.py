import logging
from autoutils import log
from autoutils.color import Colors
import json
import logging
import re
import sys

from kafka import KafkaProducer


class CustomColorfulStreamHandler(log.ColorfulStreamHandler):
    """
        A handler class which write stram handler.
    """
    LEVEL_COLOR_DATA = {
        log.NOTSET: ("NOTSET   ", Colors.CYAN_F),
        log.CRITICAL: ("CRITICAL ", Colors.BRIGHT_RED_F),
        log.ERROR: ("ERROR    ", Colors.RED_F),
        log.WARNING: ("WARNING  ", Colors.BLUE_F),
        log.INFO: ("INFO     ", Colors.GREEN_F),
        log.DEBUG: ("DEBUG    ", Colors.YELLOW_F),
    }


class KafkaHandler(logging.Handler):
    """
        A handler class which send data to logstash.
    """
    EXTRA_FIELDS = ["name", "msg", "args", "levelname", "levelno", "pathname", "filename", "module", "exc_info",
                    "exc_text", "stack_info", "lineno", "funcName", "created", "msecs", "relativeCreated", "thread",
                    "threadName", "processName", "process", "message",
                    "logger_data", "extra_data", "full_message", "app_name", "host_name"]
    LOGGER_DATA = ["name", "levelname", "levelno", "pathname", "filename", "module",
                   "exc_text", "lineno", "funcName", "created", "msecs", "relativeCreated", "thread",
                   "threadName", "processName", "process", "message"]

    def __init__(self, log_servers: list, server_name: str, topic: str = None):
        super().__init__()

        self.producer = KafkaProducer(bootstrap_servers=log_servers,
                                      value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                                      linger_ms=10)
        self.log_servers = log_servers
        self.topic = topic
        self.server_name = server_name

    def get_logger_data(self, record: "logging.LogRecord"):
        """
            Get some log data
        """
        logger_data = {}
        for key in self.LOGGER_DATA:
            logger_data[key] = getattr(record, key, None)
        return logger_data

    def get_send_data(self, record: logging.LogRecord):
        send_data = {
            "logger_data": self.get_logger_data(record=record),
        }
        for key, value in record.__dict__.items():
            if key not in self.EXTRA_FIELDS:
                if type(value) not in (bool, int, list, dict, str, float):
                    value = str(value)
                send_data[key] = value
            if key == 'args' and type(value) is dict:
                for key2, value2 in value.items():
                    if type(value2) not in (bool, int, list, dict, str, float):
                        value2 = str(value2)
                    send_data[key2] = value2

        for key in send_data.keys():
            if type(send_data[key]) is str:
                send_data[key] = remove_color_code(send_data[key])

        import datetime
        send_data['mytime'] = str(datetime.datetime.now())
        send_data['server_name'] = self.server_name
        return send_data

    def send(self, send_data: dict):
        if not self.log_servers:
            return
        self.producer.send(self.topic, send_data)
        self.producer.flush(timeout=1.0)

    def emit(self, record: logging.LogRecord) -> None:
        if not self.log_servers:
            return
        send_data = None
        send_data = self.get_send_data(record=record)
        try:
            send_data = self.get_send_data(record=record)
            self.send(send_data=send_data)

        except RecursionError:  # See issue 36272
            raise
        except Exception as e:
            if sys.stderr:
                sys.stderr.write(f"error in send to logstash {self.log_servers}. e: {e}, send_data: {send_data}\n")


def remove_color_code(text):
    # 7-bit C1 ANSI sequences
    ansi_escape = re.compile(r'''
                \x1B  # ESC
                (?:   # 7-bit C1 Fe (except CSI)
                    [@-Z\\-_]
                |     # or [ for CSI, followed by a control sequence
                    \[
                    [0-?]*  # Parameter bytes
                    [ -/]*  # Intermediate bytes
                    [@-~]   # Final byte
                )
            ''', re.VERBOSE)
    result = ansi_escape.sub('', text)
    return result
