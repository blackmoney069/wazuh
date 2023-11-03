"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

This module will contains all cases for the discard_regex test suite
"""

import pytest

# qa-integration-framework imports
from wazuh_testing import session_parameters
from wazuh_testing.modules.aws import event_monitor, local_internal_options  # noqa: F401
from wazuh_testing.modules.aws.db_utils import s3_db_exists

# Local module imports
from .utils import ERROR_MESSAGES, TIMEOUTS
from conftest import TestConfigurator

pytestmark = [pytest.mark.server]

# Set test configurator for the module
configurator = TestConfigurator(module='discard_regex_test_module')

# ---------------------------------------------------- TEST_PATH -------------------------------------------------------
# Test configuration
configurator.configure_test(configuration_file='configuration_discard_regex.yaml',
                            cases_file='cases_discard_regex.yaml')


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('configuration, metadata',
                         zip(configurator.test_configuration_template, configurator.metadata),
                         ids=configurator.cases_ids)
def test_discard_regex(
    configuration, metadata, load_wazuh_basic_configuration, set_wazuh_configuration, clean_s3_cloudtrail_db,
    configure_local_internal_options_function, truncate_monitored_files, restart_wazuh_function, file_monitoring,
):
    """
    description: Fetch logs excluding the ones that match with the regex.
    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Apply custom settings in local_internal_options.conf.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared calling the module with correct parameters.
            - Check the expected number of events were forwarded to analysisd, only logs stored in the bucket and skips
              the ones that match with regex.
            - Check the database was created and updated accordingly.
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration, both ossec.conf and local_internal_options.conf.
            - Delete the uploaded file
    wazuh_min_version: 4.6.0
    parameters:
        - configuration:
            type: dict
            brief: Get configurations from the module.
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - clean_s3_cloudtrail_db:
            type: fixture
            brief: Delete the DB file before and after the test execution.
        - configure_local_internal_options_function:
            type: fixture
            brief: Apply changes to the local_internal_options.conf configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart the wazuh service.
        - file_monitoring:
            type: fixture
            brief: Handle the monitoring of a specified file.
    assertions:
        - Check in the log that the module was called with correct parameters.
        - Check the expected number of events were forwarded to analysisd.
        - Check the database was created and updated accordingly.
    input_description:
        - The `configuration_discard_regex` file provides the module configuration for this test.
        - The `cases_discard_regex` file provides the test cases.
    """
    bucket_name = metadata['bucket_name']
    bucket_type = metadata['bucket_type']
    only_logs_after = metadata['only_logs_after']
    discard_field = metadata['discard_field']
    discard_regex = metadata['discard_regex']
    found_logs = metadata['found_logs']
    skipped_logs = metadata['skipped_logs']
    path = metadata['path'] if 'path' in metadata else None

    pattern = fr'.*The "{discard_regex}" regex found a match in the "{discard_field}" field. The event will be skipped.'

    parameters = [
        'wodles/aws/aws-s3',
        '--bucket', bucket_name,
        '--aws_profile', 'qa',
        '--only_logs_after', only_logs_after,
        '--discard-field', discard_field,
        '--discard-regex', discard_regex,
        '--type', bucket_type,
        '--debug', '2'
    ]

    if path is not None:
        parameters.insert(5, path)
        parameters.insert(5, '--trail_prefix')

    # Check AWS module started
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_start
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['failed_start']

    # Check command was called correctly
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_aws_module_called(parameters)
    )

    assert log_monitor.callback_result is not None, ERROR_MESSAGES['incorrect_parameters']

    log_monitor.start(
        timeout=TIMEOUTS[20],
        callback=event_monitor.callback_detect_event_processed_or_skipped(pattern),
        accumulations=found_logs + skipped_logs
    )

    assert s3_db_exists()

    # Detect any ERROR message
    log_monitor.start(
        timeout=session_parameters.default_timeout,
        callback=event_monitor.callback_detect_all_aws_err
    )

    assert log_monitor.callback_result is None, ERROR_MESSAGES['error_found']