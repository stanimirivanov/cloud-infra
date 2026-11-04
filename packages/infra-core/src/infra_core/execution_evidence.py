"""Bind reviewed preview observations to the exact files in signed apply admission."""

from collections.abc import Mapping
from datetime import datetime

from infra_core.preview_contracts import PreviewContract
from infra_core.preview_results import execution_binding, validate_preview_result

PREVIEW_RESULT = "preview_result"
MESSAGE = "APPLY001: preview execution evidence rejected; diagnostics withheld"


def validate_apply_preview(
    contract: PreviewContract,
    artifacts: Mapping[str, bytes],
    inputs: Mapping[str, bytes],
    *,
    now: datetime,
) -> None:
    """Validate graph, scope, clocks and exact bytes before an apply can be admitted."""
    try:
        receipt = validate_preview_result(inputs[PREVIEW_RESULT], contract, artifacts, now=now)
        if receipt.get("execution") == execution_binding(
            inputs["plan"], inputs["encrypted_configuration"]
        ):
            return
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError, RecursionError):
        pass
    raise ValueError(MESSAGE) from None
