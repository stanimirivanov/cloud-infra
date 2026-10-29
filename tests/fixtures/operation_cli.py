"""Synthetic mutation transport peer; assertions here do not prove engine semantics."""

import json
import sys
import time
from pathlib import Path

from pulumi.automation import _stack as sdk


def main():
    args = sys.argv[1:]
    assert args.pop(0) == "--non-interactive"
    with Path("calls.jsonl").open("a") as stream:
        stream.write(json.dumps(args) + "\n")
    if args[:2] == ["stack", "select"]:
        return
    if args[:2] == ["stack", "output"]:
        print("{}")
        return
    if args[:2] == ["stack", "history"]:
        print(
            json.dumps(
                [
                    dict(
                        kind="update",
                        startTime="2026-10-29T00:00:00.000000Z",
                        endTime="2026-10-29T00:00:01.000000Z",
                        message="",
                        environment={},
                        config={},
                        result="succeeded",
                        version=1,
                    )
                ]
            )
        )
        return
    case = json.loads(Path("case.json").read_text())
    if args[0] == "import":
        data = json.loads(Path(args[args.index("--file") + 1]).read_text())
        assert data == case["mapping"]
        assert "--protect=true" in args and "--generate-code=false" in args
        return
    if case.get("hang"):
        time.sleep(60)
        return
    if case.get("fail"):
        print("SYNTHETIC_PRIVATE_FAILURE", file=sys.stderr)
        sys.exit(7)
    assert args[0] in ("preview", "up")
    if args[0] == "preview":
        Path(args[args.index("--save-plan") + 1]).write_text("synthetic plan")
    else:
        assert Path(args[args.index("--plan") + 1]).read_text() == "synthetic plan"
        assert "--yes" in args and "--skip-preview" in args
    target = args[args.index("--event-log") + 1]
    assert target.startswith("tcp://127.0.0.1:")
    proto = sdk.events_pb2_grpc.pulumi_dot_events__pb2
    event = dict(
        sequence=0,
        timestamp=1,
        summaryEvent=dict(
            maybeCorrupt=False,
            durationSeconds=1,
            resourceChanges={"same": 1},
            PolicyPacks={},
            isPreview=args[0] == "preview",
        ),
    )
    with sdk.grpc.insecure_channel(target.removeprefix("tcp://")) as channel:
        sdk.grpc.channel_ready_future(channel).result(timeout=5)
        sdk.events_pb2_grpc.EventsStub(channel).StreamEvents(
            iter([proto.EventRequest(event=json.dumps(event))]), timeout=5
        )


if __name__ == "__main__":
    main()
