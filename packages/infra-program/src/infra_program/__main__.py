"""Pulumi development entry point. No deployment units are enabled in PR 1."""


def main() -> None:
    raise RuntimeError(
        "Provisioning is not enabled: backend, governance and deployment units "
        "must be implemented in subsequent reviewed PRs."
    )


if __name__ == "__main__":
    main()
