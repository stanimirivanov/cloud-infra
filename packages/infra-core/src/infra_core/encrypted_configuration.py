"""Shared ciphertext-shape checks; never decrypt or establish secret ownership."""

from typing import Any

from infra_core.operations import MAX_BYTES
from infra_core.readiness import parsed

MESSAGE = "CONFIG001: encrypted configuration rejected; private diagnostics withheld"


def validate(content: bytes, keys: set[str]) -> dict[str, Any]:
    def require(condition: bool) -> None:
        if not condition:
            raise ValueError(MESSAGE)

    try:
        require(type(content) is bytes and 0 < len(content) <= MAX_BYTES)
        value = parsed(content)
        require(
            set(value) == {"encryptionsalt", "config"}
            and type(value["encryptionsalt"]) is str
            and value["encryptionsalt"].startswith("v1:")
            and len(value["encryptionsalt"]) > 3
            and type(value["config"]) is dict
            and set(value["config"]) == keys
        )
        for secret in value["config"].values():
            require(
                type(secret) is dict
                and set(secret) == {"secure"}
                and type(secret["secure"]) is str
                and secret["secure"].startswith("v1:")
                and len(secret["secure"]) > 3
            )
        return value
    except (ValueError, TypeError, KeyError, RecursionError) as error:
        raise ValueError(MESSAGE) from error
