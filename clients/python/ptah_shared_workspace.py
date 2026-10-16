"""Shared Ptah Control workspace client handles, not a second tool scheduler.

Cookpit/Supervisor, Formula, Hunter and TTG-Simulation keep their own
decisions and approval workflows. Handles share the same canonical Ptah
Workspace, Session and Node authority stamp. Ptah owns the durable control
submission, not the caller's business truth or release approval.

Until an independently qualified E02/A05 worker is installed this interface
exposes only A14 checkpoint submission and non-execution readback.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ptah_control_client import (
    PtahBoundaryError, PtahControlClient, Submission, SubmissionStatus,
)

_ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")


@dataclass(frozen=True)
class Caller:
    tool: str
    project: str

    def __post_init__(self) -> None:
        if not (_ID.fullmatch(self.tool) and _ID.fullmatch(self.project)):
            raise PtahBoundaryError("caller tool and project require bounded identifiers")

    def context(self) -> dict[str, str]:
        return {"schema": "ptah.tool-caller.v1", "tool": self.tool,
                "project": self.project}


@dataclass(frozen=True)
class CallerReceipt:
    request_id: str
    workspace_id: str
    caller: Caller
    execution_status: str = "not_executed_by_this_control_service"


class SharedWorkspace:
    """A single underlying Ptah Control endpoint reused by many tool handles.

    No local scheduler, Node selection, subprocess or synthetic completion.
    """
    def __init__(self, control: PtahControlClient):
        self.control = control

    def for_tool(self, tool: str, project: str) -> ToolHandle:
        return ToolHandle(self.control, Caller(tool, project))


class ToolHandle:
    def __init__(self, control: PtahControlClient, caller: Caller):
        self.control = control
        self.caller = caller

    def checkpoint(self, details: dict[str, Any] | None = None) -> CallerReceipt:
        if details is not None and not isinstance(details, dict):
            raise PtahBoundaryError("checkpoint details must be a bounded mapping")
        authority = self.control.observe().authority
        workspace_id = authority["workspace_id"]
        if not isinstance(workspace_id, str) or not workspace_id:
            raise PtahBoundaryError("canonical Ptah workspace identity missing")
        context = self.caller.context()
        # Context is descriptive provenance, never a Ptah security principal.
        submission: Submission = self.control.submit_control(
            kind="checkpoint_request",
            target_id=workspace_id,
            payload={"caller_context": context, "details": details or {}},
            expected_workspace_id=workspace_id,
        )
        return CallerReceipt(submission.request_id, workspace_id, self.caller)

    def readback(self, receipt: CallerReceipt) -> SubmissionStatus:
        if receipt.caller != self.caller:
            raise PtahBoundaryError("request belongs to a different caller")
        status = self.control.read_submission(receipt.request_id)
        if (status.workspace_id != receipt.workspace_id or
                status.caller_context != self.caller.context()):
            raise PtahBoundaryError("durable request provenance mismatch")
        return status

    def run_tool(self, *_args: Any, **_kwargs: Any) -> None:
        raise PtahBoundaryError(
            "Ptah E02/A05 production tool execution is not yet qualified; "
            "Control checkpoint is not a completed tool run"
        )
