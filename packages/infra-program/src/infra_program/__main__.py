"""Pulumi development entry point. Resource deployment remains disabled in the foundation phase."""


def main() -> None:
    raise RuntimeError(
        "Provisioning is not enabled: qualified backend, governance and reviewed deployment units "
        "must be implemented in subsequent reviewed PRs."
    )


if __name__ == "__main__":
    main()
