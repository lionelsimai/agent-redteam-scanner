"""Payload library tests."""
from agent_redteam_scanner.payloads import PAYLOADS, Category, list_payloads


def test_at_least_15_payloads() -> None:
    assert len(PAYLOADS) >= 15


def test_all_categories_covered() -> None:
    cats = {p.category for p in PAYLOADS}
    assert cats == set(Category)


def test_ids_unique() -> None:
    assert len({p.id for p in PAYLOADS}) == len(PAYLOADS)


def test_filter_by_category() -> None:
    assert all(p.category == Category.TOOL_ABUSE for p in list_payloads(Category.TOOL_ABUSE))


def test_every_payload_has_patch() -> None:
    assert all(len(p.patch) > 20 for p in PAYLOADS)


def test_edge_empty_filter_result_is_list() -> None:
    assert isinstance(list_payloads(), list)
