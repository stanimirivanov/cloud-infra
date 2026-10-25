# OCI infrastructure unit

All `.tf` files here share one Terraform graph and state; file boundaries express
ownership, not independent deployment layers:

| File | Owns | Allowed references |
| --- | --- | --- |
| main.tf | Terraform/provider requirements | No resources |
| vcn.tf | VCN, subnets, gateway, routing, NSGs | Network resources and shared inputs |
| oke.tf | OKE lookups, Basic cluster, A1 node pool | Network resources and shared inputs |
| outputs.tf | Public module interface | Existing unit resources and inputs |

Network must not depend on cluster or workloads. No provisioners, local-exec,
remote-exec, external data programs, remote state reads or nested modules here.
The static sensor fails closed on unrecognized resource types/ownership changes.

Keep Basic cluster type, A1 shape and literal aggregate sizing at or below 4 OCPUs
and 24 GiB across all pools in this unit. Current configuration is two nodes,
one OCPU and 8 GiB each. These are configuration ceilings, not a billing guarantee
or a check of other tenancy resources. New capacity requires design review.

Do not expand public ingress. Existing public API TCP/6443, ICMP fragmentation
rules and unrestricted worker ingress are documented debt in HARNESS.md.
Removal or restriction is encouraged; new or changed public rules fail the
baseline policy until explicitly reviewed. Never add credentials to outputs.
