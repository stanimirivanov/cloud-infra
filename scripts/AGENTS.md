# Verification implementation

Python 3.12 implements the shared verification command. Use the standard library
except pinned HCL parsing dependencies. Run commands as argument arrays with
`check=True`; propagate failures. No shell interpolation or cloud mutation.
Render Terragrunt with synthetic inputs in a temporary copy, generate exactly
the declared files, disable the backend and validate using the provider lock.
Never run Terragrunt hooks or Terraform plan/apply in this command.

Policy changes require negative tests proving unsafe variants fail. Diagnostics
must identify the file/rule and a correction. CI and pre-commit call the same
entry point. Keep policy IDs stable so feedback is actionable.
