"""Unit tests for the token model (pure functions)."""
from oobox.tokens import (MAX_LEN, MIN_LEN, PREFIX, clamp_len, is_token, mint,
                           token_from_host, token_from_rcpt)

DOMAIN = "oob.example.com"


def test_variable_length_minting_and_recognition():
    for n in (MIN_LEN, 6, 8, 12, 20, MAX_LEN):
        t = mint(length=n)
        assert t.startswith(PREFIX) and len(t) == len(PREFIX) + n
        assert is_token(t)
        # resolves at any subdomain depth and as a recipient regardless of length
        assert token_from_host(f"deep.sub.{t}.{DOMAIN}", DOMAIN) == t
        assert token_from_rcpt(f"{t}+tag@{DOMAIN}", DOMAIN) == t


def test_length_is_clamped():
    assert clamp_len(1) == MIN_LEN
    assert clamp_len(9999) == MAX_LEN
    assert len(mint(length=1)) == len(PREFIX) + MIN_LEN
    assert len(mint(length=9999)) == len(PREFIX) + MAX_LEN


def test_mint_shape_and_uniqueness():
    seen = set()
    for _ in range(200):
        t = mint(exists=lambda x: x in seen)
        assert is_token(t)
        assert t not in seen
        seen.add(t)


def test_is_token():
    assert is_token("ob1234abcd")
    assert not is_token("ob123")          # too short
    assert not is_token("xx1234abcd")     # wrong prefix
    assert not is_token("ob1234ABCD")     # uppercase not allowed
    assert not is_token("")


def test_token_from_host():
    tok = "ob7f3k9a2x"
    assert token_from_host(f"{tok}.{DOMAIN}", DOMAIN) == tok
    assert token_from_host(f"import.{tok}.{DOMAIN}", DOMAIN) == tok
    assert token_from_host(f"{tok}.{DOMAIN}:8080", DOMAIN) == tok
    assert token_from_host(f"{tok}.{DOMAIN}.", DOMAIN) == tok
    assert token_from_host(DOMAIN, DOMAIN) is None            # apex, no token
    assert token_from_host("nope.other.com", DOMAIN) is None  # out of zone
    assert token_from_host(f"nolabel.{DOMAIN}", DOMAIN) is None


def test_token_from_rcpt():
    tok = "ob7f3k9a2x"
    assert token_from_rcpt(f"{tok}@{DOMAIN}", DOMAIN) == tok
    assert token_from_rcpt(f"{tok}+signup@{DOMAIN}", DOMAIN) == tok
    assert token_from_rcpt(f"<{tok}@{DOMAIN}>", DOMAIN) == tok
    assert token_from_rcpt(f"anyone@{tok}.{DOMAIN}", DOMAIN) == tok
    assert token_from_rcpt(f"admin@{DOMAIN}", DOMAIN) is None   # no token in address
    assert token_from_rcpt("not-an-email", DOMAIN) is None
