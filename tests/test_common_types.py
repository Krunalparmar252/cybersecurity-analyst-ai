"""Task 2: shared types live in analyst.common.types; old paths re-export them."""
from analyst.common import types as common
from analyst.reasoning import engine, patch_loop
from analyst.reporting import agent as report_agent, renderer


def test_old_and_new_import_paths_are_the_same_objects():
    assert engine.ConfirmedFinding is common.ConfirmedFinding
    assert patch_loop.ConfirmedFinding is common.ConfirmedFinding
    assert patch_loop.HUMAN_ATTENTION_STATUSES is common.HUMAN_ATTENTION_STATUSES
    assert engine.TIER_LLM == common.TIER_LLM


def test_reporting_does_not_depend_on_reasoning_for_types():
    assert report_agent.ConfirmedFinding is common.ConfirmedFinding
    assert renderer.ConfirmedFinding is common.ConfirmedFinding


def test_human_attention_statuses_content():
    assert common.HUMAN_ATTENTION_STATUSES == {"MANUAL_REVIEW_REQUIRED", "ESCALATED"}
