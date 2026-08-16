import json

import pytest

from utils.config import AppConfig, ProviderConfig


def test_builtin_provider_profile_persistence_defaults(monkeypatch):
	monkeypatch.delenv('PROVIDERS', raising=False)
	monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
	monkeypatch.delenv('CHECKIN_PERSIST_PROFILE', raising=False)

	config = AppConfig.load_from_env()

	assert config.providers['anyrouter'].persist_profile is True
	assert config.providers['agentrouter'].persist_profile is False


def test_provider_profile_persistence_can_override_builtin(monkeypatch):
	monkeypatch.setenv(
		'PROVIDERS',
		json.dumps(
			{
				'anyrouter': {'domain': 'https://anyrouter.top', 'persist_profile': False},
				'agentrouter': {'domain': 'https://agentrouter.org', 'persist_profile': True},
			}
		),
	)

	config = AppConfig.load_from_env()

	assert config.providers['anyrouter'].persist_profile is False
	assert config.providers['agentrouter'].persist_profile is True


def test_custom_provider_profile_persistence_defaults_to_false(monkeypatch):
	monkeypatch.setenv('PROVIDERS', json.dumps({'custom': {'domain': 'https://custom.example.com'}}))

	config = AppConfig.load_from_env()

	assert config.providers['custom'].persist_profile is False


def test_provider_from_dict_inherits_profile_persistence_from_defaults():
	defaults = ProviderConfig(name='custom', domain='https://old.example.com', persist_profile=True)

	provider = ProviderConfig.from_dict(
		'custom',
		{'domain': 'https://new.example.com'},
		defaults=defaults,
	)

	assert provider.persist_profile is True


def test_provider_domain_is_normalized_and_checkin_path_is_configurable():
	provider = ProviderConfig.from_dict(
		'custom',
		{'domain': 'https://custom.example.com/', 'sign_in_path': '/auth/sign-in', 'checkin_path': '/api/checkin'},
	)

	assert provider.domain == 'https://custom.example.com'
	assert provider.checkin_path == '/api/checkin'


def test_waf_configuration_cannot_fail_open():
	with pytest.raises(ValueError, match='waf_cookie_names'):
		ProviderConfig(name='custom', domain='https://custom.example.com', bypass_method='waf_cookies')


def test_provider_domain_rejects_embedded_credentials_and_query():
	with pytest.raises(ValueError, match='credentials'):
		ProviderConfig(name='custom', domain='https://user:password@example.com')
	with pytest.raises(ValueError, match='query'):
		ProviderConfig(name='custom', domain='https://example.com?token=secret')


def test_ci_disables_persistent_profiles_by_default(monkeypatch):
	monkeypatch.delenv('CHECKIN_PERSIST_PROFILE', raising=False)
	monkeypatch.setenv('GITHUB_ACTIONS', 'true')
	monkeypatch.delenv('PROVIDERS', raising=False)

	config = AppConfig.load_from_env()

	assert config.providers['anyrouter'].persist_profile is False


def test_account_config_rejects_null_api_user_for_cookie_login(monkeypatch):
	monkeypatch.setenv(
		'ANYROUTER_ACCOUNTS',
		json.dumps([{'cookies': {'session': 'session-value'}, 'api_user': None}]),
	)

	from utils.config import load_accounts_config

	assert load_accounts_config() is None


def test_account_id_is_used_for_stable_storage_key(monkeypatch):
	monkeypatch.setenv(
		'ANYROUTER_ACCOUNTS',
		json.dumps([{'id': 'stable-main', 'cookies': {'session': 'session-value'}, 'api_user': '1'}]),
	)

	from utils.config import load_accounts_config

	assert load_accounts_config()[0].get_storage_key(0) == 'stable-main'


def test_duplicate_account_ids_are_rejected(monkeypatch):
	monkeypatch.setenv(
		'ANYROUTER_ACCOUNTS',
		json.dumps(
			[
				{'id': 'same', 'cookies': {'session': 'one'}, 'api_user': '1'},
				{'id': 'same', 'cookies': {'session': 'two'}, 'api_user': '2'},
			]
		),
	)

	from utils.config import load_accounts_config

	assert load_accounts_config() is None


def test_cookie_values_and_api_user_types_are_validated(monkeypatch):
	monkeypatch.setenv(
		'ANYROUTER_ACCOUNTS',
		json.dumps([{'cookies': {'session': None}, 'api_user': '1'}]),
	)

	from utils.config import load_accounts_config

	assert load_accounts_config() is None

	monkeypatch.setenv(
		'ANYROUTER_ACCOUNTS',
		json.dumps([{'cookies': {'session': 'value'}, 'api_user': True}]),
	)

	assert load_accounts_config() is None
