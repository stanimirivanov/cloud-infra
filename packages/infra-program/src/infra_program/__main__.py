"""Standalone execution is denied; reviewed callers supply explicit preview inputs."""

from infra_program.preview_program import ServicePreviewContext, dispatch_preview


def main(context: ServicePreviewContext | None = None) -> None:
    dispatch_preview(context)


if __name__ == "__main__":
    main()
