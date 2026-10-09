import os
import json
import importlib.util
import importlib.machinery
from urllib.parse import urlparse, parse_qs

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      '..', 'getmail-gmail-xoauth-tokens')


def load_script():
    # The script name contains hyphens and has no .py suffix,
    # so load it explicitly.
    loader = importlib.machinery.SourceFileLoader('xoauth_tokens', SCRIPT)
    spec = importlib.util.spec_from_loader('xoauth_tokens', loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


mod = load_script()

# RFC 7636, Appendix B
RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_code_challenge_rfc7636_appendix_b():
    assert mod.code_challenge_s256(RFC_VERIFIER) == RFC_CHALLENGE


def test_code_verifier_format():
    v = mod.generate_code_verifier()
    assert 43 <= len(v) <= 128
    assert all(c.isalnum() or c in '-._~' for c in v)
    assert v != mod.generate_code_verifier()


def test_code_url_contains_pkce(tmp_path):
    p = tmp_path / "token.json"
    p.write_text(json.dumps({
        "scope": "https://mail.google.com/",
        "client_id": "cid",
        "auth_uri": "https://example.com/auth",
    }))
    auth = mod.OAuth2(str(p))
    auth.code_verifier = RFC_VERIFIER
    q = parse_qs(urlparse(auth.code_url(8083)).query)
    assert q['code_challenge'] == [RFC_CHALLENGE]
    assert q['code_challenge_method'] == ['S256']


def test_init_tokens_sends_code_verifier(tmp_path):
    p = tmp_path / "token.json"
    p.write_text(json.dumps({
        "client_id": "cid",
        "client_secret": "secret",
        "token_uri": "https://example.com/token",
    }))
    auth = mod.OAuth2(str(p))
    auth.code_verifier = RFC_VERIFIER
    sent = {}

    def fake_get_response(url, params):
        sent.update(params)
        return {"access_token": "a", "expires_in": 3600}

    auth.get_response = fake_get_response
    auth.init_tokens("thecode", 8083)
    assert sent['code_verifier'] == RFC_VERIFIER
    assert sent['code'] == 'thecode'
