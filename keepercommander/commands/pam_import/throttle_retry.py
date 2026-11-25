"""Shared throttle detection and retry for PAM batch import/extend.

Reuses the same policy as ``rest_api.execute_rest`` (403 ``throttled`` JSON,
server wait hints, exponential backoff) and ``workflow_apply._post_with_throttle_retry``
(message-based detection). ``api.communicate_rest`` already retries up to 3 times;
this module adds an outer retry layer for batch chunks and non-REST uploads.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Callable, Literal, Optional, TypeVar

import requests

from ...error import KeeperApiError

_T = TypeVar('_T')

OnExhausted = Literal['raise', 'repeat_max_interval']
"""After ``max_retries``: ``raise`` propagates the error; ``repeat_max_interval`` keeps
retrying at the longest progressive wait (user may abort with Ctrl-C)."""

IMPORT_ON_EXHAUSTED: OnExhausted = 'repeat_max_interval'

_THROTTLE_MSG_RE = re.compile(
    r'throttle|rate\s*limit|too many request',
    re.IGNORECASE,
)
_WAIT_RE = re.compile(r'(\d+)\s*(second|minute)', re.IGNORECASE)

DEFAULT_MAX_RETRIES = 3
BASE_BACKOFF_SECONDS = 30
MAX_WAIT_SECONDS = 300


def rest_fail_on_throttle(params) -> bool:
    """True only when ``params.rest_context.fail_on_throttle`` is explicitly enabled."""
    ctx = getattr(params, 'rest_context', None)
    if ctx is None:
        return False
    return getattr(ctx, 'fail_on_throttle', False) is True


def is_throttle_error(err: BaseException) -> bool:
    """True for Keeper 403/429 throttles and common throttle error messages."""
    if isinstance(err, KeeperApiError):
        # result_code is often a string ('throttled') but KRouter helpers also
        # raise KeeperApiError(http_status: int, body) — coerce before .lower().
        rc = err.result_code
        if rc == 429 or str(rc or '').lower() in ('throttled', '429'):
            return True
    return bool(_THROTTLE_MSG_RE.search(str(getattr(err, 'message', None) or err)))


def compute_throttle_wait(err: BaseException, attempt: int) -> float:
    """Seconds to sleep before retry (``attempt`` is 1-based; mirrors ``execute_rest``)."""
    message = ''
    if isinstance(err, KeeperApiError):
        message = err.message or ''
    else:
        message = str(err)
    wait_seconds = 60
    wait_match = _WAIT_RE.search(message)
    if wait_match:
        wait_val = int(wait_match.group(1))
        if 'minute' in wait_match.group(2).lower():
            wait_seconds = wait_val * 60
        else:
            wait_seconds = wait_val
    wait_seconds = min(wait_seconds, MAX_WAIT_SECONDS)
    return float(max(wait_seconds, BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))))


def raise_if_http_throttled(response: requests.Response) -> None:
    """Raise ``KeeperApiError('throttled', ...)`` when response is a Keeper throttle."""
    if response.status_code != 403:
        return
    content_type = response.headers.get('Content-Type') or ''
    if not content_type.startswith('application/json'):
        return
    try:
        body = response.json()
    except (ValueError, json.JSONDecodeError):
        return
    if body.get('error') == 'throttled':
        raise KeeperApiError(body.get('error', 'throttled'), body.get('message', ''))


def call_with_throttle_retry(
    fn: Callable[[], _T],
    *,
    max_retries: int = DEFAULT_MAX_RETRIES,
    label: str = '',
    fail_on_throttle: bool = False,
    on_exhausted: OnExhausted = 'raise',
) -> _T:
    """Call ``fn``; on throttle errors sleep and retry.

    Progressive wait through ``max_retries`` attempts (mirrors ``execute_rest`` backoff).
    ``on_exhausted``:
      - ``raise`` — re-raise after the last progressive retry (default).
      - ``repeat_max_interval`` — keep retrying at the longest wait until success
        (intended for long imports; operator can Ctrl-C to abort).
    """
    if fail_on_throttle:
        return fn()
    attempt = 0
    while True:
        attempt += 1
        try:
            return fn()
        except Exception as err:
            if not is_throttle_error(err):
                raise
            if attempt > max_retries and on_exhausted == 'raise':
                raise
            wait = compute_throttle_wait(err, min(attempt, max_retries))
            tag = f' ({label})' if label else ''
            if attempt <= max_retries:
                logging.warning(
                    'Throttled%s attempt %d/%d, retrying in %.0fs: %s',
                    tag, attempt, max_retries, wait, err,
                )
            else:
                logging.warning(
                    'Throttled%s attempt %d (retry every %.0fs until success; Ctrl-C to abort): %s',
                    tag, attempt, wait, err,
                )
            time.sleep(wait)


class ChunkedAddError(Exception):
    """A chunk failed with a non-throttle error; ``results`` holds the earlier chunks' results."""

    def __init__(self, results, cause: BaseException):
        super().__init__(str(cause))
        self.results = results
        self.cause = cause


def chunked_with_retry(
    params,
    records,
    send_chunk: Callable[[list], list],
    *,
    label: str = '',
    on_chunk=None,
    on_exhausted: OnExhausted = IMPORT_ON_EXHAUSTED,
    chunk_size: int = 999,
):
    """Send ``records`` in chunks, retrying throttles per chunk.

    A throttle on chunk N re-sends only chunk N, so results of chunks already
    accepted by the server are kept. Any other error raises ``ChunkedAddError``
    carrying the results gathered so far so the caller can reconcile.
    """
    results: list = []
    remaining = list(records)
    n = 0
    while remaining:
        n += 1
        chunk = remaining[:chunk_size]
        remaining = remaining[chunk_size:]
        try:
            rs = call_with_throttle_retry(
                lambda c=chunk: send_chunk(c),
                label=f'{label} chunk {n}' if label else f'chunk {n}',
                fail_on_throttle=rest_fail_on_throttle(params),
                on_exhausted=on_exhausted,
            )
        except Exception as err:
            raise ChunkedAddError(results, err) from err
        results.extend(rs)
        if on_chunk is not None:
            on_chunk(len(rs))
    return results


def execute_records_add_with_retry(
    params,
    records,
    *,
    label: str = 'records_add',
    status_type: Optional[str] = 'record',
    on_chunk=None,
    on_exhausted: OnExhausted = IMPORT_ON_EXHAUSTED,
):
    """Chunked ``vault/records_add`` with per-chunk throttle retry (raises ``ChunkedAddError``)."""
    from ... import api
    from ...importer import imp_exp
    from ...proto import record_pb2

    def _send(chunk):
        rq = api.get_records_add_request(params)
        rq.records.extend(chunk)
        rs = api.communicate_rest(params, rq, 'vault/records_add', rs_type=record_pb2.RecordsModifyResponse)
        return list(rs.records)

    results = chunked_with_retry(
        params, records, _send, label=label, on_chunk=on_chunk, on_exhausted=on_exhausted,
    )
    if status_type:
        imp_exp.report_statuses(status_type, (imp_exp.record_status_to_str(x.status) for x in results))
    return results


def execute_records_update_with_retry(
    params,
    records,
    *,
    label: str = 'records_update',
    status_type: str = 'record',
    on_exhausted: OnExhausted = IMPORT_ON_EXHAUSTED,
):
    """``imp_exp.execute_records_update`` with outer throttle retry."""
    from ...importer import imp_exp

    return call_with_throttle_retry(
        lambda: imp_exp.execute_records_update(params, records, status_type=status_type),
        label=label,
        fail_on_throttle=rest_fail_on_throttle(params),
        on_exhausted=on_exhausted,
    )
