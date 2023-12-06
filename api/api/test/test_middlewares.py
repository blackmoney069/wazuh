# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock, call, ANY
import pytest

from connexion import AsyncApp
from connexion.testing import TestContext
from connexion.exceptions import ProblemException

from freezegun import freeze_time
from wazuh.core.exception import WazuhPermissionError, WazuhTooManyRequests

from api.middlewares import check_rate_limit, unlock_ip, MAX_REQUESTS_EVENTS_DEFAULT, UNKNOWN_USER_STRING, \
    RUN_AS_LOGIN_ENDPOINT, CheckRateLimitsMiddleware, WazuhAccessLoggerMiddleware, \
    SecureHeadersMiddleware, secure_headers

@pytest.fixture
def request_info(request):
    """Return the dictionary of the parametrize"""
    return request.param if 'prevent_bruteforce_attack' in request.node.name else None

@pytest.fixture
def mock_req(request, request_info):
    """fixture to wrap functions with request"""
    req = MagicMock()
    req.client.host = 'ip'
    if 'prevent_bruteforce_attack' in request.node.name:
        for clave, valor in request_info.items():
            setattr(req, clave, valor)
    req.json = AsyncMock(side_effect=lambda: {'ctx': ''} )
    req.context = MagicMock()
    req.context.get = MagicMock(return_value={})

    return req


@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
async def test_middlewares_unlock_ip(mock_req):
    """Test unlock_ip function."""
    # Assert they are not empty
    with patch("api.middlewares.ip_stats", new={'ip': {'timestamp': 5}}) as mock_ip_stats, \
        patch("api.middlewares.ip_block", new={"ip"}) as mock_ip_block:
        unlock_ip(mock_req, 5)
        # Assert that under these conditions, they have been emptied
        assert not mock_ip_stats and not mock_ip_block


@patch("api.middlewares.ip_stats", new={"ip": {'timestamp': 5}})
@patch("api.middlewares.ip_block", new={"ip"})
@freeze_time(datetime(1970, 1, 1))
@pytest.mark.asyncio
async def test_middlewares_unlock_ip_ko(mock_req):
    """Test if `unlock_ip` raises an exception if the IP is still blocked."""
    with patch("api.middlewares.raise_if_exc") as raise_mock:
        unlock_ip(mock_req, 5)
        raise_mock.assert_called_once_with(WazuhPermissionError(6000))


@freeze_time(datetime(1970, 1, 1))
@pytest.mark.parametrize("current_time,max_requests,current_time_key, current_counter_key,expected_error_args", [
    (-80, 300, 'events_current_time', 'events_request_counter', {}),
    (-80, 300, 'general_current_time', 'general_request_counter', {}),
    (0, 0, 'events_current_time', 'events_request_counter', {
        'code': 6005,
        'extra_message': 'For POST /events endpoint the limit is set to 0 requests.'
    }),
    (0, 0, 'general_current_time', 'general_request_counter', {'code': 6001}),
])
def test_middlewares_check_rate_limit(
    current_time, max_requests, current_time_key, current_counter_key,
    expected_error_args, mock_req
):
    """Test if the rate limit mechanism triggers when the `max_requests` are reached."""

    with patch(f"api.middlewares.{current_time_key}", new=current_time), \
        patch("api.middlewares.raise_if_exc") as raise_mock:
        check_rate_limit(
            mock_req,
            current_time_key=current_time_key,
            request_counter_key=current_counter_key,
            max_requests=max_requests)
        if max_requests == 0:
            raise_mock.assert_called_once_with(WazuhTooManyRequests(**expected_error_args))


@pytest.mark.asyncio
@pytest.mark.parametrize("max_request_per_minute,endpoint", [
    (0, '/agents'),
    (30, '/agents'),
    (0, '/events'),
    (30, '/events'),
])
async def test_check_rate_limits_middleware(max_request_per_minute, endpoint, mock_req):
    """Test limits middleware."""
    response = MagicMock()
    dispatch_mock = AsyncMock(return_value=response)
    middleware = CheckRateLimitsMiddleware(AsyncApp(__name__))
    operation = MagicMock(name="operation")
    operation.method = "post"
    mock_req.url = MagicMock()
    mock_req.url.path = endpoint
    api_conf = {
        'access': {
            'max_request_per_minute': max_request_per_minute,
            'block_time': 10
        }
    }
    with TestContext(operation=operation), \
        patch('api.middlewares.unlock_ip') as mock_unlock_ip, \
        patch('api.middlewares.configuration.api_conf', api_conf), \
        patch('api.middlewares.check_rate_limit') as mock_check:
        resp = await middleware.dispatch(request=mock_req, call_next=dispatch_mock)
        dispatch_mock.assert_awaited_once_with(mock_req)
        mock_unlock_ip.assert_called_once_with(mock_req,
                                               block_time=api_conf['access']['block_time'])
        if max_request_per_minute:
            if endpoint == '/events':
                mock_check.assert_has_calls([
                    call(mock_req, 'general_request_counter',
                         'general_current_time', max_request_per_minute),
                    call(mock_req, 'events_request_counter',
                         'events_current_time', MAX_REQUESTS_EVENTS_DEFAULT),
                ], any_order=False)
            else:
                mock_check.assert_called_once_with(
                    mock_req,
                    'general_request_counter',
                    'general_current_time',
                    max_request_per_minute
                )
        assert resp == response


@pytest.mark.asyncio
@pytest.mark.parametrize("max_request_per_minute,endpoint", [
    (30, '/agents'),
    (30, '/events'),
])
async def test_check_rate_limits_middleware_ko(max_request_per_minute, endpoint, mock_req):
    """Test limits middleware."""
    def check_rate_limit(request, request_counter_key, current_time_key, max_requests):
        if (request.url.path == '/events' and request_counter_key == 'events_request_counter') or \
           (request.url.path != '/events' and request_counter_key == 'general_request_counter'):
            raise ProblemException()

    response = MagicMock()
    dispatch_mock = AsyncMock(return_value=response)
    middleware = CheckRateLimitsMiddleware(AsyncApp(__name__))
    operation = MagicMock(name="operation")
    operation.method = "post"
    mock_req.url = MagicMock()
    mock_req.url.path = endpoint
    api_conf = {
        'access': {
            'max_request_per_minute': max_request_per_minute,
            'block_time': 10
        }
    }
    with TestContext(operation=operation), \
        pytest.raises(ProblemException), \
        patch('api.middlewares.unlock_ip') as mock_unlock_ip, \
        patch('api.middlewares.configuration.api_conf', api_conf), \
        patch('api.middlewares.check_rate_limit', side_effect=check_rate_limit):
        await middleware.dispatch(request=mock_req, call_next=dispatch_mock)
        dispatch_mock.assert_not_awaited()
        mock_unlock_ip.assert_not_called()



@pytest.mark.asyncio
@pytest.mark.parametrize("json_body, q_password, b_password, b_key, user, hash, endpoint", [
    (True, None, None, None, None, 'hash', '/agents'),
    (False, 'q_pass', 'b_pass', 'b_key', 'wazuh', None, RUN_AS_LOGIN_ENDPOINT),
    (False, None, 'b_pass', 'b_key', 'wazuh', None, RUN_AS_LOGIN_ENDPOINT),
    (False, 'q_pass', None, 'b_key', 'wazuh', None, RUN_AS_LOGIN_ENDPOINT),
])
async def test_wazuh_access_logger_middleware(json_body, q_password, b_password, b_key,
                                              user, hash, endpoint, mock_req):
    """Test access logging."""
    response = MagicMock()
    response.status_code = 200
    dispatch_mock = AsyncMock(return_value=response)

    middleware = WazuhAccessLoggerMiddleware(AsyncApp(__name__), dispatch=dispatch_mock)
    operation = MagicMock(name="operation")
    operation.method = "post"

    body = {}
    body.update({'password': 'b_password'} if b_password else {})
    body.update({'key': b_key} if b_key else {})
    if json_body:
        mock_req._json = MagicMock()
    mock_req.json = AsyncMock(return_value=body )
    mock_req.query_params = {'password': q_password} if q_password else {}
    mock_req.context = {
        'token_info': {'hash_auth_context': hash} if hash else {},
    }
    mock_req.context.update({'user': user} if user else {})
    mock_req.scope = {'path': endpoint}
    mock_req.headers = {'content-type': 'None'}
    mock_blacke2b = MagicMock()
    mock_blacke2b.return_value.hexdigest.return_value = f"blackeb2 {hash}"
    with TestContext(operation=operation), \
        patch('api.middlewares.custom_logging') as mock_custom_logging, \
        patch('api.middlewares.ConnexionRequest.from_starlette_request',
              return_value=mock_req) as mock_from, \
        patch('hashlib.blake2b', mock_blacke2b):
        resp = await middleware.dispatch(request=mock_req, call_next=dispatch_mock)
        mock_from.assert_called_once_with(mock_req)
        dispatch_mock.assert_awaited_once_with(mock_req)
        if json_body:
            mock_req.json.assert_awaited_once()
        if not hash and endpoint == RUN_AS_LOGIN_ENDPOINT:
            mock_blacke2b.assert_called_once()
            hash = f"blackeb2 {hash}"
        mock_req.query_params.update({'password': '****'} if q_password else {})
        body.update({'password': '****'} if b_key else {})
        body.update({'key': '****'} if b_key and endpoint == '/agents' else {})
        mock_custom_logging.assert_called_once_with(
            user if user else UNKNOWN_USER_STRING, mock_req.client.host, mock_req.method,
            endpoint, mock_req.query_params, body, ANY, response.status_code,
            hash_auth_context=hash, headers=mock_req.headers
        )
        assert resp == response


@pytest.mark.asyncio
async def test_secure_headers_middleware(mock_req):
    """Test access logging."""
    response = MagicMock()
    dispatch_mock = AsyncMock(return_value=response)

    middleware = SecureHeadersMiddleware(AsyncApp(__name__))
    operation = MagicMock(name="operation")
    operation.method = "post"

    with TestContext(operation=operation), patch('api.middlewares.secure_headers') as mock_secure:
        secure_headers.framework.starlette = MagicMock()
        ret_response = await middleware.dispatch(request=mock_req, call_next=dispatch_mock)
        mock_secure.framework.starlette.assert_called_once_with(response)
        dispatch_mock.assert_awaited_once_with(mock_req)
        assert ret_response == response
