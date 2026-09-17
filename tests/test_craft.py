"""Unit tests for crafted victim-embedding addresses and their correlation."""
from oobox.craft import craft_addresses
from oobox.tokens import label_from_rcpt, sanitize_label, token_in_text

OOB = "oob.example.com"
VICTIM = "victim.tld"
TOK = "ob7f3k9a2x"


def test_every_crafted_address_embeds_victim_and_is_under_zone():
    for a in craft_addresses(OOB, VICTIM, TOK):
        if a["kind"] != "confusable":            # confusable swaps letters for look-alikes
            assert VICTIM in a["address"]
        host = a["address"].rsplit("@", 1)[-1]
        assert host == OOB or host.endswith("." + OOB)


def test_token_shapes_correlate_to_the_token():
    by = {a["kind"]: a for a in craft_addresses(OOB, VICTIM, TOK)}
    for kind in ("local-suffix", "local-prefix", "encoded-at", "quoted-local",
                 "comment", "sub-token-first", "sub-victim-first"):
        assert by[kind]["correlates"] == TOK, kind
    # correlates is always the real extractor result, never a guess
    for a in by.values():
        assert a["correlates"] == label_from_rcpt(a["address"], OOB)


def test_expected_shapes():
    by = {a["kind"]: a for a in craft_addresses(OOB, VICTIM, TOK)}
    assert by["local-suffix"]["address"] == f"{TOK}.{VICTIM}@{OOB}"
    assert by["local-prefix"]["address"] == f"{VICTIM}.{TOK}@{OOB}"
    assert by["sub-token-first"]["address"] == f"random@{TOK}.{VICTIM}.{OOB}"
    assert by["sub-victim-first"]["address"] == f"random@{VICTIM}.{TOK}.{OOB}"


def test_sendable_flag_only_on_clean_shapes_with_a_token():
    by = {a["kind"]: a for a in craft_addresses(OOB, VICTIM, TOK)}
    assert by["local-suffix"]["sendable"] and by["sub-token-first"]["sendable"]
    assert not by["encoded-at"]["sendable"]      # quoted/encoded/comment/confusable never sendable
    assert not by["quoted-local"]["sendable"]
    assert not by["confusable"]["deliverable"]
    # nothing is sendable without a token (no stable sender identity)
    assert not any(a["sendable"] for a in craft_addresses(OOB, VICTIM, None))


def test_tokenless_addresses_bucket_under_sanitized_victim():
    by = {a["kind"]: a for a in craft_addresses(OOB, VICTIM, None)}
    assert by["local-suffix"]["address"] == f"{VICTIM}@{OOB}"
    assert by["local-suffix"]["correlates"] == "victim-tld"


def test_token_in_text_and_sanitize():
    assert token_in_text(f"{TOK}.victim.tld") == TOK
    assert token_in_text(f'"victim.tld.{TOK}"') == TOK
    assert token_in_text("roblox.tld") is None   # 'ob' inside a victim domain is not a token
    assert sanitize_label("victim.tld") == "victim-tld"


def test_smtp_path_recovers_token_from_every_shape():
    # label_from_rcpt is what the SMTP catch-all uses to attribute mail
    for a in craft_addresses(OOB, VICTIM, TOK):
        if a["kind"] == "confusable":
            continue
        assert label_from_rcpt(a["address"], OOB) == TOK
