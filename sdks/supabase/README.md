# Supabase local SDK

Generated once with Pulumi CLI 3.272.0:

```sh
pulumi package add terraform-provider@1.5.0 --language python supabase/supabase 1.11.0
```

The resulting plugin metadata binds bridge 1.5.0 and upstream Supabase 1.11.0.
Source: https://github.com/supabase/terraform-provider-supabase/tree/v1.11.0
Integration: https://www.pulumi.com/registry/packages/supabase/

Generated Python has only trailing whitespace normalized. Reproduce that cleanup
after generation with the workspace Python:

```python
from pathlib import Path
for path in Path("sdks/supabase/pulumi_supabase").rglob("*"):
    if path.suffix not in {".py", ".pyi"}:
        continue
    source = path.read_text(encoding="utf-8")
    normalized = "\n".join(line.rstrip() for line in source.splitlines()).rstrip() + "\n"
    path.write_text(normalized, encoding="utf-8", newline="\n")
```

The packaging manifest uses the repository's pinned Hatchling build backend,
with a root README added for metadata. LICENSE.upstream retains the Supabase
provider's upstream license from the pinned source revision above.
This checked-in SDK is a uv workspace member. Builds and PR tests require no
provider binaries or SDK generation. The adapter exposes only Provider/Project;
the generated SDK's other resource classes remain forbidden by mandatory policy.
Do not edit generated Python or regenerate it during CI. Review upgrades as code.
