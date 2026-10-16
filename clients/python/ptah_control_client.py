"""Loopback-only client of Ptah's existing A14/D01 Control service.

A 202 response means authorized for dispatch, never A05 process execution.
"""
from __future__ import annotations
import ipaddress
import json
from dataclasses import dataclass
from typing import Any
from urllib import error, parse, request
from uuid import uuid4

_MAX_REPLY = 1_048_576
_PROTECTED_APPROVAL = frozenset({'submit_upgrade_activity', 'accept_worker_result'})
_ALLOWED = frozenset({
    'terminal_input', 'terminal_reconnect', 'transfer_pause', 'transfer_resume',
    'browser_navigate', 'checkpoint_request', 'workspace_reconnect',
    'advisory_dismiss', 'advisory_defer', 'advisory_choose_alternative',
    'submit_upgrade_activity', 'accept_worker_result',
})

class PtahBoundaryError(RuntimeError):
    """Authority, network or unsupported-capability boundary failed closed."""

class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PtahBoundaryError('redirect refused: endpoint authority cannot change')

@dataclass(frozen=True)
class Projection:
    snapshot: dict[str, Any]
    shell: dict[str, Any]

    @property
    def authority(self) -> dict[str, Any]:
        return self.snapshot['authority']

@dataclass(frozen=True)
class Submission:
    request_id: str
    state: str = 'authorized_for_dispatch_not_executed'

@dataclass(frozen=True)
class SubmissionStatus:
    request_id: str
    control_state: str
    execution_status: str

class PtahControlClient:
    """Same-host Ptah adapter for Hunter, Supervisor, Formula, COG and others.

    It is not a Node execution broker. Cross-host clients require Ptah's
    authenticated transport instead of turning this loopback API public.
    """
    def __init__(self, endpoint: str='http://127.0.0.1:7800', timeout: float=4):
        parts = parse.urlsplit(endpoint)
        try:
            allowed = (parts.scheme == 'http' and
                       ipaddress.ip_address(parts.hostname or '').is_loopback and
                       parts.username is None and parts.password is None and
                       parts.query == '' and parts.fragment == '' and
                       parts.path in ('', '/') and parts.port is not None)
        except (ValueError, AttributeError):
            allowed = False
        if not allowed:
            raise PtahBoundaryError('only explicit loopback Ptah Control endpoints accepted')
        if not (0 < timeout <= 30):
            raise ValueError('timeout must be bounded (0,30]')
        self.endpoint = endpoint.rstrip('/')
        self.timeout = timeout
        self.opener = request.build_opener(_NoRedirect)

    def _json(self, path: str, payload: dict[str, Any] | None=None,
              status: int=200) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload, separators=(',', ':')).encode()
        if body is not None and len(body) > 65_536:
            raise PtahBoundaryError('request exceeds bounded size')
        headers={'Accept':'application/json', 'Content-Type':'application/json',
                 'Cache-Control':'no-store'}
        if body is not None:
            # Match the real Ptah A14 protected POST same-origin requirement.
            headers['Origin']=self.endpoint
        req = request.Request(
            self.endpoint + path, data=body, headers=headers,
            method='GET' if payload is None else 'POST')
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                if response.status != status:
                    raise PtahBoundaryError(f'Ptah response {response.status}; expected {status}')
                raw = response.read(_MAX_REPLY+1)
                if len(raw) > _MAX_REPLY:
                    raise PtahBoundaryError('Ptah response too large')
                value = json.loads(raw)
                if not isinstance(value, dict):
                    raise PtahBoundaryError('Ptah response must be an object')
                return value
        except error.HTTPError as exc:
            exc.close()
            raise PtahBoundaryError(f'Ptah operation rejected: HTTP {exc.code}') from exc
        except (error.URLError, OSError, json.JSONDecodeError) as exc:
            raise PtahBoundaryError(f'Ptah operation unavailable or rejected: {exc}') from exc

    def observe(self) -> Projection:
        state = self._json('/api/state')
        shell = self._json('/api/shell-v2')
        authority = state.get('authority')
        if not isinstance(authority, dict) or authority != shell.get('authority'):
            raise PtahBoundaryError('Ptah authority stamp mismatch; cannot use stale projection')
        for field in ('workspace_id','session_id','node_id','fence','provider_generations'):
            if field not in authority:
                raise PtahBoundaryError('incomplete canonical authority stamp')
        return Projection(state, shell)

    def submit_control(self, *, kind: str, target_id: str, payload: dict[str, Any],
                       approval_id: str | None=None, provider_id: str | None=None,
                       expected_provider_generation: int | None=None) -> Submission:
        if kind not in _ALLOWED:
            raise PtahBoundaryError('operation is not in Ptah A14 ControlKind')
        if not target_id or not isinstance(payload, dict):
            raise PtahBoundaryError('target and payload required')
        if kind in _PROTECTED_APPROVAL and not approval_id:
            raise PtahBoundaryError('independent caller approval required')
        if provider_id is not None and expected_provider_generation is None:
            raise PtahBoundaryError('provider generation required for provider-bound action')
        projection = self.observe()
        request_id = str(uuid4())
        result = self._json('/api/control', {
            'request_id':request_id,'kind':kind,'target_id':target_id,
            'expected':projection.authority,'provider_id':provider_id,
            'expected_provider_generation':expected_provider_generation,
            'approval_id':approval_id,'payload':payload}, status=202)
        if result.get('request_id') != request_id:
            raise PtahBoundaryError('Ptah returned an unexpected submission identity')
        return Submission(request_id)


    def read_submission(self, request_id: str) -> SubmissionStatus:
        # Look up the exact durably recorded control request after process
        # restart. This API does not claim Node execution or result acceptance.
        if (not isinstance(request_id, str) or
                not 1 <= len(request_id) <= 128 or
                not all(c.isascii() and (c.isalnum() or c == '-') for c in request_id)):
            raise PtahBoundaryError('invalid bounded submission identity')
        result = self._json('/api/submissions/' + request_id)
        if result.get('request_id') != request_id:
            raise PtahBoundaryError('submission read-back identity mismatch')
        if (result.get('control_state') != 'authorized_for_dispatch' or
                result.get('execution_status') != 'not_executed_by_this_control_service'):
            raise PtahBoundaryError('no independently qualified execution status')
        return SubmissionStatus(
            request_id, result['control_state'], result['execution_status'])
