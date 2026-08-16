#!/usr/bin/env python3
"""
配置管理模块
"""

import json
import os
from dataclasses import dataclass
from typing import Dict, List, Literal
from urllib.parse import urlsplit


def _env_bool(name: str, default: bool) -> bool:
	"""读取布尔环境变量，非法值按默认值处理。"""
	raw = os.getenv(name)
	if raw is None:
		return default
	return raw.strip().lower() in {'1', 'true', 'yes', 'on'}


@dataclass
class ProviderConfig:
	"""Provider 配置"""

	name: str
	domain: str
	login_path: str = '/login'
	sign_in_path: str | None = '/api/user/sign_in'
	checkin_path: str | None = '/api/user/checkin'
	user_info_path: str = '/api/user/self'
	api_user_key: str = 'new-api-user'
	bypass_method: Literal['waf_cookies'] | None = None
	waf_cookie_names: List[str] | None = None
	use_proxy: bool = False
	persist_profile: bool = False

	def __post_init__(self):
		if not isinstance(self.domain, str):
			raise ValueError('provider domain must be a string')
		parsed = urlsplit(self.domain)
		if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
			raise ValueError('provider domain must be an absolute http(s) URL')
		if parsed.username or parsed.password or parsed.query or parsed.fragment:
			raise ValueError('provider domain must not include credentials, query, or fragment')
		self.domain = self.domain.rstrip('/')

		if self.bypass_method not in {None, 'waf_cookies'}:
			raise ValueError(f'unsupported bypass_method: {self.bypass_method}')
		if self.waf_cookie_names is None:
			cleaned_names: list[str] = []
		elif isinstance(self.waf_cookie_names, list):
			cleaned_names = []
			for item in self.waf_cookie_names:
				if not isinstance(item, str) or not item.strip():
					raise ValueError('waf_cookie_names must contain non-empty strings')
				cleaned_names.append(item.strip())
		else:
			raise ValueError('waf_cookie_names must be a list')

		self.waf_cookie_names = list(dict.fromkeys(cleaned_names))
		if self.bypass_method == 'waf_cookies' and not self.waf_cookie_names:
			raise ValueError('bypass_method=waf_cookies requires waf_cookie_names')

		for field_name in ('login_path', 'sign_in_path', 'checkin_path', 'user_info_path'):
			value = getattr(self, field_name)
			if value is not None and (not isinstance(value, str) or not value.startswith('/')):
				raise ValueError(f'{field_name} must be an absolute path starting with /')
		if not isinstance(self.api_user_key, str) or not self.api_user_key.strip():
			raise ValueError('api_user_key must be a non-empty string')

	@classmethod
	def from_dict(cls, name: str, data: dict, *, defaults: 'ProviderConfig | None' = None) -> 'ProviderConfig':
		"""从字典创建 ProviderConfig

		配置格式:
		- 基础: {"domain": "https://example.com"}
		- 完整: {"domain": "https://example.com", "login_path": "/login", "use_proxy": true, ...}
		"""
		default_use_proxy = defaults.use_proxy if defaults else False
		default_persist_profile = defaults.persist_profile if defaults else False
		return cls(
			name=name,
			domain=data['domain'],
			login_path=data.get('login_path', defaults.login_path if defaults else '/login'),
			sign_in_path=data.get('sign_in_path', defaults.sign_in_path if defaults else '/api/user/sign_in'),
			checkin_path=data.get('checkin_path', defaults.checkin_path if defaults else '/api/user/checkin'),
			user_info_path=data.get('user_info_path', defaults.user_info_path if defaults else '/api/user/self'),
			api_user_key=data.get('api_user_key', defaults.api_user_key if defaults else 'new-api-user'),
			bypass_method=data.get('bypass_method', defaults.bypass_method if defaults else None),
			waf_cookie_names=data.get('waf_cookie_names', defaults.waf_cookie_names if defaults else None),
			use_proxy=data.get('use_proxy', default_use_proxy),
			persist_profile=data.get('persist_profile', default_persist_profile),
		)

	def needs_waf_cookies(self) -> bool:
		"""判断是否需要获取 WAF cookies"""
		return self.bypass_method == 'waf_cookies'

	def needs_manual_check_in(self) -> bool:
		"""判断是否需要手动调用签到接口"""
		return self.sign_in_path is not None


@dataclass
class AppConfig:
	"""应用配置"""

	providers: Dict[str, ProviderConfig]

	@classmethod
	def load_from_env(cls) -> 'AppConfig':
		"""从环境变量加载配置"""
		persist_profile_default = _env_bool(
			'CHECKIN_PERSIST_PROFILE',
			os.getenv('GITHUB_ACTIONS', '').strip().lower() != 'true',
		)
		providers = {
			'anyrouter': ProviderConfig(
				name='anyrouter',
				domain='https://anyrouter.top',
				login_path='/login',
				sign_in_path='/api/user/sign_in',
				user_info_path='/api/user/self',
				checkin_path='/api/user/checkin',
				api_user_key='new-api-user',
				bypass_method='waf_cookies',
				waf_cookie_names=['acw_tc', 'cdn_sec_tc', 'acw_sc__v2'],
				use_proxy=False,
				persist_profile=persist_profile_default,
			),
			'agentrouter': ProviderConfig(
				name='agentrouter',
				domain='https://agentrouter.org',
				login_path='/login',
				sign_in_path=None,  # 无需签到接口，查询用户信息时自动完成签到
				user_info_path='/api/user/self',
				checkin_path='/api/user/checkin',
				api_user_key='new-api-user',
				bypass_method='waf_cookies',
				waf_cookie_names=['acw_tc'],
				use_proxy=True,
				persist_profile=False,
			),
		}

		# 尝试从环境变量加载自定义 providers
		providers_str = os.getenv('PROVIDERS')
		if providers_str:
			try:
				providers_data = json.loads(providers_str)

				if not isinstance(providers_data, dict):
					print('[WARNING] PROVIDERS must be a JSON object, ignoring custom providers')
					return cls(providers=providers)

				# 解析自定义 providers,会覆盖默认配置
				for name, provider_data in providers_data.items():
					try:
						providers[name] = ProviderConfig.from_dict(
							name,
							provider_data,
							defaults=providers.get(name),
						)
					except Exception as e:
						print(f'[WARNING] Failed to parse provider "{name}": {e}, skipping')
						continue

				print(f'[INFO] Loaded {len(providers_data)} custom provider(s) from PROVIDERS environment variable')
			except json.JSONDecodeError as e:
				print(
					f'[WARNING] Failed to parse PROVIDERS environment variable: {e}, using default configuration only'
				)
			except Exception as e:
				print(f'[WARNING] Error loading PROVIDERS: {e}, using default configuration only')

		return cls(providers=providers)

	def get_provider(self, name: str) -> ProviderConfig | None:
		"""获取指定 provider 配置"""
		return self.providers.get(name)


@dataclass
class AccountConfig:
	"""账号配置"""

	cookies: dict | str | None
	api_user: str | None = None
	provider: str = 'anyrouter'
	name: str | None = None
	email: str | None = None
	password: str | None = None
	id: str | None = None

	@classmethod
	def from_dict(cls, data: dict, index: int) -> 'AccountConfig':
		"""从字典创建 AccountConfig"""
		provider = data.get('provider', 'anyrouter')
		name = data.get('name', f'Account {index + 1}')
		api_user = data.get('api_user')
		if api_user is not None:
			api_user = str(api_user).strip()

		return cls(
			cookies=data.get('cookies'),
			api_user=api_user,
			provider=provider,
			name=name if name else None,
			email=data.get('email'),
			password=data.get('password'),
			id=data.get('id'),
		)

	def has_login_credentials(self) -> bool:
		"""是否配置了邮箱密码登录"""
		return bool(self.email and self.password)

	def get_display_name(self, index: int) -> str:
		"""获取显示名称"""
		return self.name if self.name else f'Account {index + 1}'

	def get_storage_key(self, index: int) -> str:
		"""获取余额历史使用的稳定账号键，未配置 id 时兼容旧索引键。"""
		return self.id.strip() if isinstance(self.id, str) and self.id.strip() else f'account_{index + 1}'


def load_accounts_config() -> list[AccountConfig] | None:
	"""从环境变量加载账号配置"""
	accounts_str = os.getenv('ANYROUTER_ACCOUNTS')
	if not accounts_str:
		print('ERROR: ANYROUTER_ACCOUNTS environment variable not found')
		return None

	try:
		accounts_data = json.loads(accounts_str)
	except json.JSONDecodeError as e:
		print(f'ERROR: ANYROUTER_ACCOUNTS JSON 解析失败: {e}')
		print('HINT: 常见原因 - 末尾多余逗号、使用了单引号、包含注释、或换行格式问题')
		return None

	try:
		if not isinstance(accounts_data, list):
			print('ERROR: Account configuration must use array format [{}]')
			return None

		accounts = []
		seen_ids: set[str] = set()
		for i, account_dict in enumerate(accounts_data):
			if not isinstance(account_dict, dict):
				print(f'ERROR: Account {i + 1} configuration format is incorrect')
				return None

			if 'api_user' not in account_dict:
				has_login = (
					isinstance(account_dict.get('email'), str)
					and bool(account_dict.get('email', '').strip())
					and isinstance(account_dict.get('password'), str)
					and bool(account_dict.get('password', '').strip())
				)
				if not has_login:
					print(
						f'ERROR: Account {i + 1} missing required field (api_user) - only email+password login can omit it'
					)
					return None
			elif account_dict.get('api_user') is not None and (
				isinstance(account_dict.get('api_user'), bool)
				or not isinstance(account_dict.get('api_user'), (str, int))
				or not str(account_dict.get('api_user')).strip()
			):
				print(f'ERROR: Account {i + 1} api_user must be a non-empty string or integer')
				return None

			has_cookies = 'cookies' in account_dict and bool(account_dict['cookies'])
			has_login = (
				isinstance(account_dict.get('email'), str)
				and bool(account_dict.get('email', '').strip())
				and isinstance(account_dict.get('password'), str)
				and bool(account_dict.get('password', '').strip())
			)
			if has_cookies and (
				'api_user' not in account_dict
				or account_dict.get('api_user') is None
				or not str(account_dict.get('api_user')).strip()
			):
				print(f'ERROR: Account {i + 1} cookie login requires a non-empty api_user')
				return None

			if not has_cookies and not has_login:
				print(f'ERROR: Account {i + 1} must have either cookies or email+password')
				return None

			if has_cookies and not isinstance(account_dict.get('cookies'), (dict, str)):
				print(f'ERROR: Account {i + 1} cookies must be an object or cookie header string')
				return None
			if isinstance(account_dict.get('cookies'), str) and not account_dict['cookies'].strip():
				print(f'ERROR: Account {i + 1} cookies cannot be empty')
				return None
			if isinstance(account_dict.get('cookies'), dict):
				for cookie_name, cookie_value in account_dict['cookies'].items():
					if not isinstance(cookie_name, str) or not cookie_name.strip() or not isinstance(cookie_value, str):
						print(f'ERROR: Account {i + 1} cookies must map non-empty names to string values')
						return None
			if account_dict.get('email') is not None and not isinstance(account_dict.get('email'), str):
				print(f'ERROR: Account {i + 1} email must be a string')
				return None
			if account_dict.get('password') is not None and not isinstance(account_dict.get('password'), str):
				print(f'ERROR: Account {i + 1} password must be a string')
				return None
			if 'provider' in account_dict and (
				not isinstance(account_dict['provider'], str) or not account_dict['provider'].strip()
			):
				print(f'ERROR: Account {i + 1} provider field must be a non-empty string')
				return None

			if 'name' in account_dict and (
				not isinstance(account_dict['name'], str) or not account_dict['name'].strip()
			):
				print(f'ERROR: Account {i + 1} name field cannot be empty')
				return None
			if 'id' in account_dict and (not isinstance(account_dict['id'], str) or not account_dict['id'].strip()):
				print(f'ERROR: Account {i + 1} id field must be a non-empty string')
				return None
			account_id = account_dict.get('id')
			if isinstance(account_id, str) and account_id.strip():
				account_id = account_id.strip()
				if account_id in seen_ids:
					print(f'ERROR: Account {i + 1} id field must be unique')
					return None
				seen_ids.add(account_id)

			accounts.append(AccountConfig.from_dict(account_dict, i))

		return accounts
	except Exception as e:
		print(f'ERROR: Account configuration format is incorrect: {e}')
		return None
