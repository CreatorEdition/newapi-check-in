import pytest

import checkin
from utils.browser import BrowserLoginResult
from utils.config import AccountConfig, AppConfig, ProviderConfig
from utils.newapi_client import CheckinResult, CheckinStatus


def _app_config(*, waf: bool = False) -> AppConfig:
	provider = ProviderConfig(
		name='custom',
		domain='https://example.com',
		bypass_method='waf_cookies' if waf else None,
		waf_cookie_names=['acw_tc'] if waf else None,
	)
	return AppConfig(providers={'custom': provider})


def _result(status: CheckinStatus, message: str = 'test') -> checkin.CheckInRunResult:
	return checkin.CheckInRunResult(
		success=status in {CheckinStatus.SUCCESS, CheckinStatus.ALREADY_SIGNED},
		user_info_before=None,
		user_info_after=None,
		status=status,
		message=message,
	)


def test_run_api_attempt_sends_newapi_token_headers(monkeypatch):
	captured = {}

	class FakeClient:
		def __init__(self):
			self.cookies = {}

		def __enter__(self):
			return self

		def __exit__(self, exc_type, exc_value, traceback):
			return False

	def fake_client(**kwargs):
		return FakeClient()

	def fake_user_info(client, headers, user_info_url):
		captured.update(headers)
		return {
			'success': True,
			'quota': 1.0,
			'used_quota': 0.0,
			'display': 'balance',
		}

	monkeypatch.setattr(checkin.httpx, 'Client', fake_client)
	monkeypatch.setattr(checkin, 'get_user_info', fake_user_info)
	monkeypatch.setattr(
		checkin,
		'execute_check_in',
		lambda client, account_name, provider_config, headers: CheckinResult(
			CheckinStatus.SUCCESS,
			'签到成功',
		),
	)

	account = AccountConfig(cookies=None, api_user='12345', provider='custom')
	result = checkin.run_check_in_requests(
		{},
		account,
		'Account 1',
		_app_config().providers['custom'],
		api_token='api-key-value',
	)

	assert result.success
	assert captured['Authorization'] == 'Bearer api-key-value'
	assert captured['new-api-user'] == '12345'


@pytest.mark.asyncio
async def test_api_key_success_does_not_start_browser(monkeypatch):
	calls = []

	def fake_run(all_cookies, account, account_name, provider_config, **kwargs):
		calls.append((all_cookies, kwargs))
		return _result(CheckinStatus.SUCCESS)

	async def browser_must_not_run(*args, **kwargs):
		raise AssertionError('browser fallback should not run after API success')

	monkeypatch.setattr(checkin, 'run_check_in_requests', fake_run)
	monkeypatch.setattr(checkin, 'login_with_credentials', browser_must_not_run)
	monkeypatch.setattr(checkin, 'prepare_cookies', browser_must_not_run)

	account = AccountConfig(
		cookies={'session': 'fallback'},
		api_user='12345',
		api_key='api-key-value',
		email='user@example.com',
		password='password-value',
		provider='custom',
	)
	result = await checkin.check_in_account(account, 0, _app_config())

	assert result.success
	assert len(calls) == 1
	assert calls[0][1]['api_token'] == 'api-key-value'
	assert calls[0][0] == {}


@pytest.mark.asyncio
async def test_failed_token_falls_back_to_cookie_api_before_browser(monkeypatch):
	calls = []

	def fake_run(all_cookies, account, account_name, provider_config, **kwargs):
		calls.append((all_cookies, kwargs))
		if kwargs.get('api_token'):
			return _result(CheckinStatus.NEEDS_LOGIN, 'token expired')
		return _result(CheckinStatus.SUCCESS)

	async def browser_must_not_run(*args, **kwargs):
		raise AssertionError('cookie API fallback should finish before browser')

	monkeypatch.setattr(checkin, 'run_check_in_requests', fake_run)
	monkeypatch.setattr(checkin, 'login_with_credentials', browser_must_not_run)

	account = AccountConfig(
		cookies={'session': 'fallback'},
		api_user='12345',
		api_key='expired-api-key',
		email='user@example.com',
		password='password-value',
		provider='custom',
	)
	result = await checkin.check_in_account(account, 0, _app_config())

	assert result.success
	assert len(calls) == 2
	assert calls[0][1]['api_token'] == 'expired-api-key'
	assert calls[1][1].get('api_token') is None
	assert calls[1][0] == {'session': 'fallback'}


@pytest.mark.asyncio
async def test_waf_browser_is_only_started_after_api_challenge(monkeypatch):
	calls = []
	prepared = {'session': 'fallback', 'acw_tc': 'fresh-waf-cookie'}

	def fake_run(all_cookies, account, account_name, provider_config, **kwargs):
		calls.append((all_cookies, kwargs))
		if all_cookies.get('acw_tc') == 'fresh-waf-cookie':
			return _result(CheckinStatus.SUCCESS)
		return _result(CheckinStatus.NEEDS_HUMAN, 'cloudflare challenge')

	async def fake_prepare(account_name, provider_config, user_cookies):
		return prepared

	async def browser_login_must_not_run(*args, **kwargs):
		raise AssertionError('email/password browser login should not run after WAF refresh succeeds')

	monkeypatch.setattr(checkin, 'run_check_in_requests', fake_run)
	monkeypatch.setattr(checkin, 'prepare_cookies', fake_prepare)
	monkeypatch.setattr(checkin, 'login_with_credentials', browser_login_must_not_run)

	account = AccountConfig(cookies=None, api_user='12345', api_key='api-key-value', provider='custom')
	result = await checkin.check_in_account(account, 0, _app_config(waf=True))

	assert result.success
	assert len(calls) == 2
	assert calls[0][0] == {}
	assert calls[1][0] == prepared
	assert calls[1][1]['api_token'] == 'api-key-value'


@pytest.mark.asyncio
async def test_browser_login_is_last_resort_after_api_failure(monkeypatch):
	calls = []

	def fake_run(all_cookies, account, account_name, provider_config, **kwargs):
		calls.append((all_cookies, kwargs))
		if len(calls) == 1:
			return _result(CheckinStatus.NEEDS_LOGIN, 'token expired')
		return _result(CheckinStatus.SUCCESS)

	async def fake_login(*args, **kwargs):
		return BrowserLoginResult(cookies={'session': 'fresh'}, api_user='67890')

	monkeypatch.setattr(checkin, 'run_check_in_requests', fake_run)
	monkeypatch.setattr(checkin, 'login_with_credentials', fake_login)

	account = AccountConfig(
		cookies=None,
		api_user='12345',
		api_key='expired-api-key',
		email='user@example.com',
		password='password-value',
		provider='custom',
	)
	result = await checkin.check_in_account(account, 0, _app_config())

	assert result.success
	assert len(calls) == 2
	assert calls[1][0] == {'session': 'fresh'}
	assert calls[1][1]['api_user_override'] == '67890'
	assert calls[1][1].get('api_token') is None
