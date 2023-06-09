'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-analysisd' daemon receives the log messages and compares them to the rules.
       It then creates an alert when a log message matches an applicable rule.
       Specifically, these tests will check if the 'wazuh-analysisd' daemon correctly handles
       incoming events related to file scanning.

components:
    - analysisd

suite: scan_messages

targets:
    - manager

daemons:
    - wazuh-analysisd
    - wazuh-db

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html

tags:
    - events
'''
import pytest

from pathlib import Path

from wazuh_testing import session_parameters
from wazuh_testing.constants.daemons import WAZUH_DB_DAEMON, ANALYSISD_DAEMON
from wazuh_testing.constants.paths.sockets import WAZUH_DB_SOCKET_PATH, ANALYSISD_QUEUE_SOCKET_PATH
from wazuh_testing.modules.analysisd import callbacks, ANALYSISD_DEBUG_CONFIG
from wazuh_testing.tools import mitm
from wazuh_testing.utils import config

from . import TEST_CASES_PATH


pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configuration and cases data.
cases_path = Path(TEST_CASES_PATH, 'cases_scan_messages.yaml')

# Test configurations.
_, metadata, cases_ids = config.get_test_cases_data(cases_path)

# Test internal options.
local_internal_options = ANALYSISD_DEBUG_CONFIG

# Test variables.
receiver_sockets_params = [(ANALYSISD_QUEUE_SOCKET_PATH, 'AF_UNIX', 'UDP')]

mitm_wdb = mitm.ManInTheMiddle(address=WAZUH_DB_SOCKET_PATH, family='AF_UNIX', connection_protocol='TCP')
mitm_analysisd = mitm.ManInTheMiddle(address=ANALYSISD_QUEUE_SOCKET_PATH, family='AF_UNIX', connection_protocol='UDP')
monitored_sockets_params = [(WAZUH_DB_DAEMON, mitm_wdb, True), (ANALYSISD_DAEMON, mitm_analysisd, True)]

receiver_sockets, monitored_sockets = None, None  # Set in the fixtures


# Test function.
@pytest.mark.parametrize('metadata', metadata, ids=cases_ids)
def test_scan_messages(metadata, configure_local_internal_options, configure_sockets_environment,
                       connect_to_sockets, wait_for_analysisd_startup):
    '''
    description: Check if when the 'wazuh-analysisd' daemon socket receives a message with
                 a file scanning-related event, it generates the corresponding alert
                 that sends to the 'wazuh-db' daemon socket.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options.
        - configure_sockets_environment:
            type: fixture
            brief: Configure environment for sockets and MITM.
        - connect_to_sockets:
            type: fixture
            brief: Connect to a given list of sockets.
        - wait_for_analysisd_startup:
            type: fixture
            brief: Wait until the 'wazuh-analysisd' has begun and the 'alerts.json' file is created.

    assertions:
        - Verify that the messages generated are consistent with the events received.

    input_description: Different test cases that are contained in an external YAML file (scan_messages.yaml)
                       that includes 'syscheck' events data and the expected output.

    expected_output:
        - Multiple messages (scan status logs) corresponding to each test case,
          located in the external input data file.

    tags:
        - man_in_the_middle
        - wdb_socket
    '''
    # Start monitor
    receiver_sockets[0].send(metadata['input'])
    monitored_sockets[0].start(callback=callbacks.callback_wazuh_db_message, timeout=session_parameters.default_timeout)

    # Check that expected message appears
    expected = callbacks.callback_analysisd_message(metadata['output'])
    assert monitored_sockets[0].callback_result == expected, 'Failed test case stage: {}'.format(metadata['stage'])