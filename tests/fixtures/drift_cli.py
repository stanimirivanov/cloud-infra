"""Synthetic refresh-preview peer: closed flags, no cloud or actual engine behavior."""

import json
import sys
import time
from pathlib import Path

from pulumi.automation import _stack as sdk

args = sys.argv[1:]
assert "--non-interactive" in args and args[0] in {"refresh", "preview"}
if args[0] == "refresh":
    assert "--preview-only" in args and "--run-program" in args and "--yes" not in args
    assert "--policy-pack" not in args
else:
    assert "--refresh=false" in args and "--policy-pack" in args
case = json.loads(Path("case.json").read_bytes())
print("SYNTHETIC_PRIVATE_OUTPUT", file=sys.stderr)
if case["fault"] == "timeout":
    time.sleep(30)
if case["fault"] == "exit":
    sys.exit(7)
refresh = args[0] == "refresh"
policy = "" if refresh else args[args.index("--policy-pack") + 1]
values = (
    []
    if refresh
    else [
        dict(
            policyAnalyzeSummaryEvent=dict(
                policyPackName="always-free-governance", passed=["reviewed-resource-costs"]
            )
        )
    ]
)
values += [
    dict(
        summaryEvent=dict(
            isPreview=True,
            result="succeeded",
            maybeCorrupt=False,
            resourceChanges={"delete": 1} if case["fault"] == "deleted" else {"same": 1},
            PolicyPacks={} if refresh else {"always-free-governance|local|" + policy: "0.0.1"},
        )
    ),
    dict(cancelEvent={}),
]
if case["fault"] == "incomplete":
    values.pop()
uri = args[args.index("--event-log") + 1]
assert uri.startswith("tcp://127.0.0.1:")
proto = sdk.events_pb2_grpc.pulumi_dot_events__pb2
with sdk.grpc.insecure_channel(uri.removeprefix("tcp://")) as channel:
    sdk.grpc.channel_ready_future(channel).result(timeout=5)
    sdk.events_pb2_grpc.EventsStub(channel).StreamEvents(
        iter(
            proto.EventRequest(event=json.dumps(dict(sequence=i, timestamp=1, **event)))
            for i, event in enumerate(values)
        ),
        timeout=5,
    )
