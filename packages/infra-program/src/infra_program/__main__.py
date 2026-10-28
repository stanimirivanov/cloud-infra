"""Standalone execution is denied; reviewed callers supply explicit preview inputs."""

from infra_program.preview_program import (
    NetworkPreviewContext,
    ServicePreviewContext,
    dispatch_preview,
)


def main(context: ServicePreviewContext | NetworkPreviewContext | None = None) -> None:
    dispatch_preview(context)


if __name__ == "__main__":
    main()
