"""Synthetic CLI process for SDK transport tests; never a cloud/engine implementation."""

import json
import sys
import time
from pathlib import Path

from pulumi.automation import _stack as sdk


def main():
    args = sys.argv[1:]
    assert "--non-interactive" in args
    if args[:2] == ["stack", "select"]:
        return
    assert args[0] == "preview" and args[-1] == "--refresh=false"
    case = json.loads(Path("synthetic-events.json").read_bytes())
    print("SYNTHETIC_PRIVATE_STDOUT")
    print("SYNTHETIC_PRIVATE_STDERR", file=sys.stderr)
    if case["hang"]:
        time.sleep(30)
        return
    target = args[args.index("--event-log") + 1]
    assert target.startswith("tcp://127.0.0.1:")
    proto = sdk.events_pb2_grpc.pulumi_dot_events__pb2
    with sdk.grpc.insecure_channel(target.removeprefix("tcp://")) as channel:
        sdk.grpc.channel_ready_future(channel).result(timeout=5)
        sdk.events_pb2_grpc.EventsStub(channel).StreamEvents(
            iter(proto.EventRequest(event=raw) for raw in case["events"]), timeout=5
        )


if __name__ == "__main__":
    main()
