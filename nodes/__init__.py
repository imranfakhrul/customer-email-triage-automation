"""LangGraph pipeline nodes for Customer Email Triage Automation."""

from nodes.ingest import ingest_node, should_continue_triage

__all__ = ["ingest_node", "should_continue_triage"]
