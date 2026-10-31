"""Independent synthetic engine states for the existing service component contract."""

from copy import deepcopy

from infra_core.services.governance import DNS, PROJECT


def service_events(configuration):
    unit, provider = configuration["unit"], configuration["provider"]
    prefix = f"urn:pulumi:{unit}::free-infrastructure::"
    root = prefix + "pulumi:pulumi:Stack::free-infrastructure-" + unit
    component_type = "infrastructure:services:Independent"
    component = prefix + component_type + "::" + unit
    provider_type = "pulumi:providers:" + provider
    provider_urn = prefix + component_type + "$" + provider_type + "::" + unit + "-provider"
    secret = {
        "4dabf18193072939515e22adb298388d": "1b47061264138c4ac30d75fd1eb44270",
        "ciphertext": "[secret]",
    }
    endpoint = (
        {"apiToken": secret, "baseUrl": "https://api.cloudflare.com/client/v4"}
        if provider == "cloudflare"
        else {"accessToken": secret, "endpoint": "https://api.supabase.com"}
    )
    states = [
        dict(
            urn=root, type="pulumi:pulumi:Stack", parent="", custom=False, protect=False, inputs={}
        ),
        dict(
            urn=component, type=component_type, parent=root, custom=False, protect=True, inputs={}
        ),
        dict(
            id="fixture-id",
            urn=provider_urn,
            type=provider_type,
            parent=component,
            custom=True,
            protect=True,
            inputs=endpoint,
        ),
    ]
    for item in configuration["resources"]:
        props = deepcopy(item["props"])
        if provider == "supabase":
            props["databasePassword"] = secret
        kind = DNS if provider == "cloudflare" else PROJECT
        states.append(
            dict(
                urn=prefix + component_type + "$" + kind + "::" + unit + "-" + item["key"],
                type=kind,
                parent=component,
                custom=True,
                protect=True,
                provider=provider_urn + "::fixture-id",
                inputs=props,
            )
        )
    result = []
    for state in states:
        metadata = dict(
            op="create",
            urn=state["urn"],
            type=state["type"],
            new=state,
            provider=state.get("provider", ""),
        )
        for kind in ("resourcePreEvent", "resOutputsEvent"):
            result.append((kind, dict(planning=True, metadata=deepcopy(metadata))))
    return result


def oci_events(unit, cfg, account, dependency=None):
    from infra_core.oci.graph import Ref, network_graph, oke_graph, wire

    prefix = f"urn:pulumi:{unit}::free-infrastructure::"
    root = prefix + "pulumi:pulumi:Stack::free-infrastructure-" + unit
    kind = "infrastructure:oci:" + ("Network" if unit == "oci-network" else "Oke")
    component = prefix + kind + "::" + cfg.name + ("-network" if unit == "oci-network" else "-oke")
    provider = prefix + "pulumi:providers:oci::" + cfg.name + "-provider"
    states = [
        dict(
            urn=root, type="pulumi:pulumi:Stack", parent="", inputs={}, custom=False, protect=False
        ),
        dict(urn=component, type=kind, parent=root, inputs={}, custom=False, protect=True),
        dict(
            urn=provider,
            type="pulumi:providers:oci",
            parent=root,
            inputs={"region": cfg.region, "tenancyOcid": account["account_id"]},
            id="oci-provider-id",
            custom=True,
            protect=True,
        ),
    ]
    if dependency is not None:
        builtin = prefix + "pulumi:providers:pulumi::default"
        states += [
            dict(
                urn=builtin,
                type="pulumi:providers:pulumi",
                parent="",
                inputs={},
                id="builtin-id",
                custom=True,
                protect=False,
            ),
            dict(
                urn=prefix + "pulumi:pulumi:StackReference::" + cfg.name + "-network-reference",
                type="pulumi:pulumi:StackReference",
                id="organization/free-infrastructure/oci-network",
                parent=root,
                inputs={"name": "organization/free-infrastructure/oci-network"},
                external=True,
                outputs={
                    "name": "organization/free-infrastructure/oci-network",
                    "outputs": dependency,
                    "secretOutputNames": [],
                },
                provider=builtin + "::builtin-id",
                custom=True,
                protect=False,
            ),
        ]
    graph = (
        network_graph(cfg)
        if unit == "oci-network"
        else oke_graph(cfg, dependency["network"]["ids"])
    )

    def bind(value):
        if isinstance(value, Ref):
            return "synthetic-" + value.key
        if isinstance(value, dict):
            return {k: bind(v) for k, v in value.items()}
        if isinstance(value, list):
            return [bind(v) for v in value]
        return value

    for item in graph:
        states.append(
            dict(
                urn=prefix + kind + "$" + item.kind + "::" + cfg.name + "-" + item.key,
                type=item.kind,
                parent=component,
                provider=provider + "::oci-provider-id",
                id="synthetic-" + item.key,
                inputs=wire(bind(item.props)),
                custom=True,
                protect=True,
            )
        )
    records = []
    for state in states:
        metadata = dict(
            op="read" if state["type"] == "pulumi:pulumi:StackReference" else "create",
            urn=state["urn"],
            type=state["type"],
            new=state,
            provider=state.get("provider", ""),
        )
        for kind in ("resourcePreEvent", "resOutputsEvent"):
            records.append((kind, dict(planning=True, metadata=deepcopy(metadata))))
    return records
