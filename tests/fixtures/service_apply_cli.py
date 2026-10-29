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
assert args[0] in ("preview", "up", "import")
if args[0] != "import":
    assert "--refresh=false" in args and "--policy-pack" in args
if args[0] == "up":
    assert "--yes" in args and "--skip-preview" in args
    assert Path(args[args.index("--plan") + 1]).read_bytes() == b"synthetic-plan"
case = json.loads(Path("case.json").read_text())
fault = case["fault"]
if args[0] == "import":
    assert json.loads(Path(args[args.index("--file") + 1]).read_bytes()) == case["mapping"]
    assert "--protect=true" in args and "--generate-code=false" in args
    assert "--plan" not in args and "--policy-pack" not in args
print("SYNTHETIC_PRIVATE_OUTPUT")
if fault == "timeout":
    time.sleep(30)
if fault == "exit":
    sys.exit(7)
policy = args[args.index("--policy-pack") + 1] if args[0] != "import" else ""
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
if args[0] == "import":
    events.pop(0)
    events[0]["summaryEvent"]["PolicyPacks"] = {}
    events[0]["summaryEvent"]["resourceChanges"] = {"import": len(case["mapping"]["resources"])}
if fault == "post-change" and args[0] == "preview":
    events[1]["summaryEvent"]["resourceChanges"] = {"update": 1}
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
