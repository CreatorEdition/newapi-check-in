from utils.proxy import mask_proxy_url


def test_mask_proxy_url_removes_credentials_and_query():
	assert mask_proxy_url('http://user:password@example.com:7890?token=secret') == 'http://example.com:7890'


def test_mask_proxy_url_handles_invalid_values():
	assert mask_proxy_url(None) == '<not configured>'
