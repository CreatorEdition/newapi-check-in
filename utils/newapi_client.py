"""NewAPI 请求、响应解析与签到结果分类。"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, cast

import httpx


class CheckinStatus(StrEnum):
	"""签到执行结果状态。"""

	SUCCESS = 'success'
	ALREADY_SIGNED = 'already_signed'
	NEEDS_LOGIN = 'needs_login'
	NEEDS_HUMAN = 'needs_human'
	DISABLED = 'disabled'
	FAILED = 'failed'


@dataclass(frozen=True)
class CheckinResult:
	"""一次签到请求的脱敏结果。"""

	status: CheckinStatus
	message: str
	diagnostics: dict[str, Any] = field(default_factory=dict)

	@property
	def succeeded(self) -> bool:
		"""判断结果是否代表签到成功或今日已签到。"""
		return self.status in {CheckinStatus.SUCCESS, CheckinStatus.ALREADY_SIGNED}


def normalize_message(value: object) -> str:
	"""将 API 返回的任意消息值归一为短字符串。"""
	if value is None:
		return ''
	if isinstance(value, (list, tuple)):
		return '; '.join(item for item in (normalize_message(item) for item in value) if item)
	if isinstance(value, dict):
		for key in ('message', 'msg', 'error_description', 'error', 'detail'):
			if key in value:
				message = normalize_message(value[key])
				if message:
					return message
		return ''
	return str(value).strip()


def redact_message(value: object) -> str:
	"""脱敏并限制服务端消息长度，避免凭据进入日志或通知。"""
	return (
		re.sub(
			r'(authorization|access[_ -]?token|refresh[_ -]?token|api[_ -]?key|cookie|jwt|secret|password)\s*[:=]\s*(?:Bearer\s+)?\S+',
			r'\1=<redacted>',
			normalize_message(value),
			flags=re.IGNORECASE,
		)
		.replace('\r', ' ')
		.replace('\n', ' ')[:240]
	)


def _response_json(response: Any) -> object | None:
	"""安全读取响应 JSON，解析失败时返回 None。"""
	try:
		return cast(object | None, response.json())
	except (ValueError, TypeError, AttributeError):
		return None


def _response_text(response: Any) -> str:
	"""安全读取响应文本并限制诊断长度。"""
	try:
		return str(response.text or '')[:4000]
	except (AttributeError, TypeError):
		return ''


def _response_headers(response: Any) -> str:
	"""读取响应头文本，避免依赖具体 HTTP 客户端类型。"""
	try:
		return '\n'.join(f'{key}: {value}' for key, value in response.headers.items()).lower()
	except (AttributeError, TypeError):
		return ''


def is_html_challenge(response: Any) -> bool:
	"""识别 WAF、Cloudflare 或验证码 HTML 页面。"""
	text = _response_text(response).lower()
	headers = _response_headers(response)
	return (
		'content-type: text/html' in headers
		or '<!doctype html' in text[:800]
		or '<html' in text[:800]
		or 'cf-chl-' in text
		or 'cloudflare' in text
		or '请进行验证' in text
		or 'verify you are human' in text
	)


def _message_from_payload(payload: object, response: Any) -> str:
	"""提取常见 API envelope 中的消息。"""
	if isinstance(payload, dict):
		message = normalize_message(
			payload.get('message')
			or payload.get('msg')
			or payload.get('error_description')
			or payload.get('error')
			or payload.get('detail')
		)
		if message:
			return message
	return '' if payload is not None else f'HTTP {getattr(response, "status_code", 0)} 返回非 JSON'


def _is_envelope_success(status_code: int, payload: object) -> bool:
	"""判断常见 NewAPI/OneAPI 响应 envelope 是否成功。"""
	if not 200 <= status_code < 300 or not isinstance(payload, dict):
		return False
	if 'success' in payload and isinstance(payload['success'], bool):
		return payload['success']
	if 'code' in payload:
		return payload['code'] in {0, '0', 200, '200', 'SUCCESS'}
	if 'ret' in payload:
		return payload['ret'] in {1, '1', True}
	message = normalize_message(payload.get('message') or payload.get('msg') or payload.get('detail'))
	return any(keyword in message.lower() for keyword in ('success', 'successful', 'ok', '签到成功', '签到完成'))


def _has_already_message(message: str) -> bool:
	"""判断消息是否表示今日已经签到。"""
	text = message.lower()
	return any(
		keyword in text
		for keyword in ('今日已签到', '今天已经签到', '已经签到', '已签到', 'already checked', 'already signed')
	)


def _is_auth_failure(status_code: int, message: str) -> bool:
	"""判断响应是否表示登录态或访问令牌失效。"""
	text = message.lower()
	return status_code in {401, 403} or any(
		keyword in text
		for keyword in (
			'unauthorized',
			'forbidden',
			'not logged',
			'login required',
			'invalid token',
			'token expired',
			'未登录',
			'请登录',
			'权限不足',
			'无权进行此操作',
			'认证失败',
		)
	)


def _is_human_verification(message: str) -> bool:
	"""判断响应是否要求验证码或人工验证。"""
	text = message.lower()
	return any(
		keyword in text for keyword in ('turnstile', 'captcha', '验证码', '人机验证', 'cloudflare', 'waf', 'pow')
	)


def _is_feature_disabled(message: str) -> bool:
	"""判断站点是否明确关闭签到功能。"""
	text = message.lower()
	return any(
		keyword in text
		for keyword in (
			'签到功能未启用',
			'签到功能已关闭',
			'签到功能未开启',
			'签到已关闭',
			'签到功能不可用',
			'签到关闭',
			'未开启签到',
			'签到未开启',
			'check-in is not enabled',
			'checkin is not enabled',
			'check-in disabled',
			'checkin disabled',
		)
	)


def classify_response(response: Any, *, stage: str = 'checkin') -> CheckinResult:
	"""将 HTTP 响应转换为统一的脱敏签到结果。"""
	try:
		status_code = int(getattr(response, 'status_code', 0) or 0)
	except (TypeError, ValueError):
		status_code = 0
	text = _response_text(response)
	payload = _response_json(response)
	message = redact_message(_message_from_payload(payload, response))
	if not message and text and payload is None:
		message = f'HTTP {status_code} 返回非 JSON'

	diagnostics: dict[str, Any] = {
		'stage': stage,
		'httpStatus': status_code,
		'isHtmlChallenge': is_html_challenge(response),
		'isJson': payload is not None,
	}
	if diagnostics['isHtmlChallenge']:
		return CheckinResult(CheckinStatus.NEEDS_HUMAN, '站点返回 WAF/验证码页面', diagnostics)
	if _has_already_message(message):
		return CheckinResult(CheckinStatus.ALREADY_SIGNED, message, diagnostics)
	if _is_envelope_success(status_code, payload):
		return CheckinResult(CheckinStatus.SUCCESS, message or '签到成功', diagnostics)
	if _is_auth_failure(status_code, message):
		return CheckinResult(CheckinStatus.NEEDS_LOGIN, message or '登录态或访问令牌无效', diagnostics)
	if _is_human_verification(message):
		return CheckinResult(CheckinStatus.NEEDS_HUMAN, message or '需要人工验证', diagnostics)
	if _is_feature_disabled(message):
		return CheckinResult(CheckinStatus.DISABLED, message or '站点已关闭签到功能', diagnostics)
	if status_code in {404, 405}:
		return CheckinResult(CheckinStatus.FAILED, message or f'签到端点不存在（HTTP {status_code}）', diagnostics)
	return CheckinResult(CheckinStatus.FAILED, message or f'签到失败（HTTP {status_code}）', diagnostics)


def execute_checkin_request(
	client: Any,
	base_url: str,
	headers: dict[str, str],
	sign_in_path: str,
	*,
	checkin_path: str = '/api/user/checkin',
	timeout: float = 30.0,
	body: dict[str, Any] | None = None,
	retries: int = 2,
) -> CheckinResult:
	"""按 sign_in -> checkin 顺序执行有限端点回退和网络退避。"""
	from urllib.parse import urljoin

	base = f'{base_url.rstrip("/")}/'
	has_body = bool(body)
	if has_body:
		attempts = [(checkin_path, True, body)]
	else:
		attempts = [(sign_in_path, False, None)]
		if sign_in_path.rstrip('/') != checkin_path.rstrip('/'):
			attempts.append((checkin_path, True, {}))

	last_result: CheckinResult | None = None
	for index, (path, include_json, payload) in enumerate(attempts):
		request_headers = {key: value for key, value in headers.items() if key.lower() != 'content-type'}
		if include_json:
			request_headers['Content-Type'] = 'application/json'
		result: CheckinResult | None = None
		for retry_index in range(max(1, retries)):
			try:
				request_kwargs = {
					'headers': request_headers,
					'timeout': timeout,
				}
				if include_json:
					request_kwargs['json'] = payload
				response = client.post(urljoin(base, path.lstrip('/')), **request_kwargs)
				result = classify_response(response)
			except httpx.RequestError as exc:
				result = CheckinResult(
					CheckinStatus.FAILED,
					f'签到请求异常: {type(exc).__name__}',
					{'stage': 'checkin', 'httpStatus': 0, 'errorType': type(exc).__name__},
				)
			except Exception as exc:
				result = CheckinResult(
					CheckinStatus.FAILED,
					f'签到请求异常: {type(exc).__name__}',
					{'stage': 'checkin', 'httpStatus': 0, 'errorType': type(exc).__name__},
				)
				break

			status_code = result.diagnostics.get('httpStatus', 0)
			should_retry = (
				result.status is CheckinStatus.FAILED
				and (not status_code or status_code in {408, 425, 429} or status_code >= 500)
				and retry_index + 1 < max(1, retries)
			)
			if not should_retry:
				break
			time.sleep(0.25 * (2**retry_index))

		assert result is not None
		if result.status in {
			CheckinStatus.SUCCESS,
			CheckinStatus.ALREADY_SIGNED,
			CheckinStatus.NEEDS_HUMAN,
			CheckinStatus.DISABLED,
		}:
			return result
		last_result = result
		if index + 1 == len(attempts):
			return result

	return last_result or CheckinResult(CheckinStatus.FAILED, '未发现可用的签到端点')
