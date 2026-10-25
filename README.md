# OCI OKE infrastructure

Terraform and Terragrunt provision OCI networking and an OKE Basic cluster with
an Ampere A1 node pool. The current configuration has two nodes, each with one
OCPU and 8 GiB RAM. It targets Always Free sizing but cannot guarantee zero cost,
capacity or tenancy eligibility. Tekton installation is not implemented.

Start with [HARNESS.md](HARNESS.md) for the architecture map, scoped agent guides,
local setup, deterministic checks, CI gates and hardening roadmap.

```text
terraform/root.hcl                    Shared generated backend/provider/variables
terraform/01-infrastructure/vcn.tf    VCN, API/node/pod subnets, routing and NSGs
terraform/01-infrastructure/oke.tf    Basic cluster, OCI lookups and A1 nodes
terraform/01-infrastructure/outputs.tf  cluster_ocid and region
```

## Development verification

Install the pinned tools documented in HARNESS.md, activate the Python virtual
environment and run:

```sh
python -m pip install -r scripts/requirements.txt
pre-commit install
python scripts/verify.py
```

This validates formatting, architecture, policy regression tests and provider
schema without OCI credentials or state access. No resources are provisioned.

## Provisioning prerequisites

Use an OCI account, API signing key and the GitHub environment
`oci-infrastructure` with these secrets:

- OCI_CLI_USER, OCI_CLI_TENANCY, OCI_CLI_FINGERPRINT, OCI_CLI_KEY_CONTENT
- OCI_CLI_REGION, OCI_COMPARTMENT_OCID
- OCI_S3_ACCESS_KEY, OCI_S3_SECRET_KEY for the pre-existing S3-compatible backend

For authorized local provisioning, export the corresponding `TF_VAR_tenancy_ocid`,
`TF_VAR_user_ocid`, `TF_VAR_fingerprint`, `TF_VAR_private_key`, `TF_VAR_region` and
`TF_VAR_compartment_ocid`, plus backend AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY.
The root.hcl file owns backend location and state keys; do not replace them with
local state. Treat `terraform.tfvars.example` as documentation only: Terragrunt
inputs come from environment variables. Never commit real credentials or state.

Run Terragrunt from `terraform/01-infrastructure`; plain Terraform in the parent
`terraform/` directory does not generate the required configuration. Inspect an
authorized `terragrunt plan` before requesting any apply. Cluster access requires
OCI tooling and the `cluster_ocid` output; there is no kubeconfig command output.

## CI/CD

The Harness workflow runs credential-free checks on every PR and main push. The
Terragrunt Deployment workflow runs for Terraform changes and manual dispatch,
requires the same gate, and retains the owner/environment controls for its
credentialed plan and main apply. See HARNESS.md for required repository settings,
known network/image/recovery risks and the staged hardening plan.
