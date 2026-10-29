"""Synthetic peer for apply transport; never an engine or cloud implementation."""

import json
import sys
import time
from pathlib import Path

from pulumi.automation import _stack as sdk

args = sys.argv[1:]
assert "--non-interactive" in args
if args[:2] == ["stack", "select"]:
    sys.exit(0)
if args[:2] == ["stack", "export"]:
    assert "--show-secrets" not in args
    Path(args[args.index("--file") + 1]).write_bytes(b"synthetic-checkpoint")
    sys.exit(0)
assert args[0] in ("preview", "up") and "--refresh=false" in args
assert "--policy-pack" in args
if args[0] == "up":
    assert "--yes" in args and "--skip-preview" in args
    assert Path(args[args.index("--plan") + 1]).read_bytes() == b"synthetic-plan"
fault = json.loads(Path("case.json").read_text())["fault"]
print("SYNTHETIC_PRIVATE_OUTPUT")
if fault == "timeout":
    time.sleep(30)
if fault == "exit":
    sys.exit(7)
policy = args[args.index("--policy-pack") + 1]
events = [
    dict(
        sequence=0,
        timestamp=1,
        policyAnalyzeSummaryEvent={
            "policyPackName": "always-free-governance",
            "passed": ["reviewed-resource-costs"],
        },
    ),
    dict(
        sequence=1,
        timestamp=1,
        summaryEvent=dict(
            isPreview=args[0] == "preview",
            result="succeeded",
            maybeCorrupt=False,
            resourceChanges={"same": 1},
            PolicyPacks={"always-free-governance|local|" + policy: "0.0.1"},
        ),
    ),
    dict(sequence=2, timestamp=1, cancelEvent={}),
]
if fault == "incomplete":
    events.pop()
uri = args[args.index("--event-log") + 1]
assert uri.startswith("tcp://127.0.0.1:")
proto = sdk.events_pb2_grpc.pulumi_dot_events__pb2
with sdk.grpc.insecure_channel(uri.removeprefix("tcp://")) as channel:
    sdk.grpc.channel_ready_future(channel).result(timeout=5)
    sdk.events_pb2_grpc.EventsStub(channel).StreamEvents(
        iter(proto.EventRequest(event=json.dumps(e)) for e in events), timeout=5
    )
