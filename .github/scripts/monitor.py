"""Protected scheduling entry; no provider credentials are loaded by check/delivery/watchdog."""

import argparse
import os
from pathlib import Path

from infra_core import incidents as i
from infra_program import monitoring as m


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    for name in ("initialize", "check", "drift", "collect", "deliver", "watchdog"):
        mode.add_argument("--" + name, action="store_true")
    parser.add_argument("--allow-delivery", action="store_true")
    args = parser.parse_args()
    try:
        root = Path(__file__).resolve().parents[2]
        source = dict(os.environ)
        i.require(not args.allow_delivery or args.watchdog)
        if not args.drift:
            i.require(
                not any(k.startswith(("AWS_", "OCI_", "PULUMI_")) and v for k, v in source.items())
            )
        if args.initialize:
            m.initialize(root, source)
            print("MONITOR: new empty local state initialized")
        elif args.check:
            result = m.preflight(root, source)
            if source.get("GITHUB_OUTPUT"):
                with Path(source["GITHUB_OUTPUT"]).open("a") as output:
                    output.write("drift_admitted=" + str(result["drift_admitted"]).lower() + "\n")
                    output.write("duplicate=" + str(result["duplicate"]).lower() + "\n")
            print(
                "CHECK: drift admitted"
                if result["drift_admitted"]
                else "CHECK: drift unavailable; observation will be unknown"
            )
        elif args.drift:
            m.run_drift(root, source, lambda: m.credentials(source, source["MONITOR_UNIT"]))
            print("DRIFT: observation recorded")
        elif args.collect:
            state = m.collect(root, source)
            print("MONITOR: " + state["severity"] + "; pending=" + str(len(state["pending"])))
        elif args.deliver:
            state = m.deliver(root, source, lambda: source["MONITOR_DELIVERY_TOKEN"])
            print("DELIVERY: pending=" + str(len(state["pending"])))
        else:
            result = m.watchdog(
                root,
                source,
                delivery=args.allow_delivery,
                token=lambda: source["MONITOR_DELIVERY_TOKEN"],
            )
            print(
                "WATCHDOG: "
                + ", ".join(unit + "=" + status for unit, status in sorted(result.items()))
            )
        return 0
    except RuntimeError as error:
        print(i.PERSISTENCE if str(error) == i.PERSISTENCE else i.MESSAGE)
        return 1
    except Exception:
        print(i.MESSAGE)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
