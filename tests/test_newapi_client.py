from utils.newapi_client import CheckinStatus, classify_response, execute_checkin_request


class FakeResponse:
	def __init__(self, status_code, payload=None, text='', headers=None):
		self.status_code = status_code
		self._payload = payload
		self.text = text
		self.headers = headers or {'content-type': 'application/json'}

	def json(self):
		if self._payload is None:
			raise ValueError('not json')
		return self._payload


class FakeClient:
	def __init__(self, responses):
		self.responses = list(responses)
		self.calls = []

	def post(self, url, **kwargs):
		self.calls.append((url, kwargs))
		return self.responses.pop(0)


def test_sign_in_falls_back_to_checkin_without_json_header():
	client = FakeClient(
		[
			FakeResponse(404, {'message': 'not found'}),
			FakeResponse(200, {'success': True, 'message': '签到成功'}),
		]
	)

	result = execute_checkin_request(client, 'https://example.com', {'Accept': 'application/json'}, '/api/user/sign_in')

	assert result.status is CheckinStatus.SUCCESS
	assert len(client.calls) == 2
	first_headers = client.calls[0][1]['headers']
	second_headers = client.calls[1][1]['headers']
	assert 'Content-Type' not in first_headers
	assert second_headers['Content-Type'] == 'application/json'
	assert client.calls[0][1].get('json') is None
	assert client.calls[1][1]['json'] == {}


def test_response_statuses_are_classified_without_leaking_body():
	assert classify_response(FakeResponse(401, {'message': 'token expired'})).status is CheckinStatus.NEEDS_LOGIN
	assert classify_response(FakeResponse(200, {'msg': '今日已签到'})).status is CheckinStatus.ALREADY_SIGNED
	assert (
		classify_response(
			FakeResponse(
				403, text='<!doctype html><html>verify you are human</html>', headers={'content-type': 'text/html'}
			)
		).status
		is CheckinStatus.NEEDS_HUMAN
	)
	assert (
		classify_response(FakeResponse(200, {'code': 500, 'message': {'detail': '签到关闭'}})).status
		is CheckinStatus.DISABLED
	)


def test_checkin_body_skips_sign_in_endpoint():
	client = FakeClient([FakeResponse(200, {'ret': 1, 'msg': 'ok'})])

	result = execute_checkin_request(
		client,
		'https://example.com/',
		{},
		'/api/user/sign_in',
		body={'captcha_id': 'id', 'captcha_answer': 'answer'},
	)

	assert result.succeeded
	assert len(client.calls) == 1
	assert client.calls[0][0] == 'https://example.com/api/user/checkin'


def test_classify_response_accepts_newapi_code_zero():
	result = classify_response(FakeResponse(200, {'code': '0', 'data': {}}))

	assert result.status is CheckinStatus.SUCCESS


def test_unknown_error_envelope_is_not_treated_as_success():
	result = classify_response(FakeResponse(200, {'error': '签到失败'}))

	assert result.status is CheckinStatus.FAILED


def test_explicit_success_false_takes_precedence_over_code_zero():
	result = classify_response(FakeResponse(200, {'success': False, 'code': 0, 'message': '失败'}))

	assert result.status is CheckinStatus.FAILED


def test_transient_server_error_is_retried_before_fallback():
	client = FakeClient(
		[
			FakeResponse(503, {'message': 'temporary'}),
			FakeResponse(200, {'ret': 1, 'msg': 'ok'}),
		]
	)

	result = execute_checkin_request(client, 'https://example.com', {}, '/api/user/sign_in')

	assert result.succeeded
	assert len(client.calls) == 2


def test_response_message_is_redacted_and_limited():
	result = classify_response(FakeResponse(401, {'message': 'authorization: Bearer very-secret-token'}))

	assert result.status is CheckinStatus.NEEDS_LOGIN
	assert 'very-secret-token' not in result.message
