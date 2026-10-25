# Terraform and Terragrunt boundaries

`root.hcl` owns backend, OCI provider and common variable generation. Child units
include it; never duplicate those blocks in checked-in `.tf` files. State keys
derive from `path_relative_to_include()`; renaming a unit is a state migration.
Never put cloud calls, shell hooks or credential defaults into validation paths.

Use snake_case Terraform labels, descriptive variable/output documentation,
explicit types and sensitive secret inputs. Format with `terraform fmt -recursive
terraform` and `terragrunt hcl fmt --working-dir terraform` using pinned tools.
Commit `.terraform.lock.hcl` when dependencies change; do not use `init -upgrade`
in ordinary verification. Provider upgrades require schema validation and review.

Keep the single current state unit until a dependency/state migration design is
approved. Future cluster add-ons (including Tekton) belong in a separate unit
consuming cluster outputs, not in the network or shared provider generator.
Do not add Helm/Kubernetes providers to the OCI infrastructure unit.
