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
