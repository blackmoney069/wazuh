# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import collections
import logging
import re
from pythonjsonlogger import jsonlogger

from api.configuration import api_conf
from api.api_exception import APIError
from api.util import APILoggerSize

# Compile regex when the module is imported so it's not necessary to compile it everytime log.info is called
request_pattern = re.compile(r'\[.+]|\s+\*\s+')

# Variable used to specify an unknown user
UNKNOWN_USER_STRING = "unknown_user"

# Run_as login endpoint path
RUN_AS_LOGIN_ENDPOINT = "/security/user/authenticate/run_as"


class WazuhJsonFormatter(jsonlogger.JsonFormatter):
    """
    Define the custom JSON log formatter used by wlogging.
    """

    def add_fields(self, log_record: collections.OrderedDict, record: logging.LogRecord, message_dict: dict):
        """Implement custom logic for adding fields in a log entry.

        Parameters
        ----------
        log_record : collections.OrderedDict
            Dictionary with custom fields used to generate a log entry.
        record : logging.LogRecord
            Contains all the information to the event being logged.
        message_dict : dict
            Dictionary with a request or exception information.
        """
        # Request handling
        if record.message is None:
            record.message = {
                'type': 'request',
                'payload': message_dict
            }
        else:
            # Traceback handling
            traceback = message_dict.get('exc_info')
            if traceback is not None:
                record.message = {
                    'type': 'error',
                    'payload': f'{record.message}. {traceback}'
                }
            else:
                # Plain text messages
                record.message = {
                    'type': 'informative',
                    'payload': record.message
                }
        log_record['timestamp'] = self.formatTime(record, self.datefmt)
        log_record['levelname'] = record.levelname
        log_record['data'] = record.message


def set_logging(log_filepath, log_level='INFO', foreground_mode=False) -> dict:
    """Set up logging for API.
    
    This function creates a logging configuration dictionary, configure the wazuh-api logger
    and returns the logging configuration dictionary that will be used in uvicorn logging
    configuration.
    
    Parameters
    ----------
    log_path : str
        Log file path.
    log_level :  str
        Logger Log level.
    foreground_mode: bool
        Log output to console streams when true
        else Log output to file.

    Raise
    -----
    
    Returns
    -------
    log_config_dict : dict
        Logging configuraction dictionary.
    """
    handlers = {
        'plainfile': None, 
        'jsonfile': None,
    }
    if foreground_mode:
        handlers.update({'console': {}})
    else:
        if 'json' in api_conf['logs']['format']:
            handlers["jsonfile"] = {
                'filename': f"{log_filepath}.json",
                'formatter': 'json',
                'filters': ['json-filter'],
            }
        if 'plain' in api_conf['logs']['format']:
            handlers["plainfile"] = {
                'filename': f"{log_filepath}.log",
                'formatter': 'log',
                'filters': ['plain-filter'],
            }

    hdls = [k for k, v in handlers.items() if isinstance(v, dict)]
    if not hdls:
        raise APIError(2011)

    log_config_dict = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "()": "uvicorn.logging.DefaultFormatter",
                "fmt": "%(levelprefix)s %(message)s",
                "use_colors": None,
            },
            "access": {
                "()": "uvicorn.logging.AccessFormatter",
                "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
            },
            "log": {
                "()": "uvicorn.logging.DefaultFormatter",
                "fmt": "%(asctime)s %(levelname)s: %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
                "use_colors": None,
            },
            "json" : {
                '()': 'api.alogging.WazuhJsonFormatter',
                'style': '%',
                'datefmt': "%Y/%m/%d %H:%M:%S"
            }
        },
        "filters": {
            'plain-filter': {'()': 'wazuh.core.wlogging.CustomFilter',
                             'log_type': 'log' },
            'json-filter': {'()': 'wazuh.core.wlogging.CustomFilter',
                             'log_type': 'json' }
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr",
            },
            "access": {
                "formatter": "access",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout"
            },
            "console": {
                'formatter': 'log',
                'class': 'logging.StreamHandler',
                'stream': 'ext://sys.stdout',
                'filters': ['plain-filter']
            },
        },
        "loggers": {
            "wazuh-api": {"handlers": hdls, "level": log_level, "propagate": False},
            "start-stop-api": {"handlers": hdls, "level": 'INFO', "propagate": False}
        }
    }

    # configure file handlers
    for handler, d in handlers.items():
        if d and 'filename' in d:
            if api_conf['logs']['max_size']['enabled']:
                max_size = APILoggerSize(api_conf['logs']['max_size']['size']).size
                d.update({
                    'class':'wazuh.core.wlogging.SizeBasedFileRotatingHandler',
                    'maxBytes': max_size,
                    'backupCount': 1
                })
            else:
                d.update({
                    'class': 'wazuh.core.wlogging.TimeBasedFileRotatingHandler',
                    'when': 'midnight'
                })
            log_config_dict['handlers'][handler] = d

    # Configure the uvicorn loggers. They will be created by the uvicorn server.
    log_config_dict['loggers']['uvicorn'] = {"handlers": hdls, "level": 'WARNING', "propagate": False}
    log_config_dict['loggers']['uvicorn.error'] = {"handlers": hdls, "level": 'WARNING', "propagate": False}
    log_config_dict['loggers']['uvicorn.access'] = {'level': 'WARNING'}

    return log_config_dict
