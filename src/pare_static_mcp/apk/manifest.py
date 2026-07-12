from __future__ import annotations


def parse(apk) -> dict:
    """Parse AndroidManifest.xml and return a structured summary.

    Exported inference: a component is exported if android:exported is
    explicitly "true", OR (effective target SDK < 31 AND the component has
    at least one intent-filter AND android:exported is not explicitly "false").
    This mirrors Android's pre-31 implicit-export rule.

    androguard 4.1.3 note: get_attribute_value(tag, attr, name=n) is the
    correct accessor for per-component attributes; get_element() does not
    exist in this version.
    """
    target = apk.get_effective_target_sdk_version()
    activities = apk.get_activities()
    services = apk.get_services()
    receivers = apk.get_receivers()
    providers = apk.get_providers()

    exported: list[str] = []
    for kind, names in (
        ("activity", activities),
        ("service", services),
        ("receiver", receivers),
        ("provider", providers),
    ):
        for n in names:
            exp = apk.get_attribute_value(kind, "exported", name=n)
            ifs = apk.get_intent_filters(kind, n)
            is_exp = (str(exp).lower() == "true") or (
                exp is None and ifs and target < 31
            )
            if is_exp:
                exported.append(n)

    return {
        "permissions": apk.get_permissions(),
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "providers": providers,
        "application_class": apk.get_attribute_value("application", "name"),
        "exported": exported,
        "debuggable": apk.get_attribute_value("application", "debuggable") == "true",
        "allow_backup": apk.get_attribute_value("application", "allowBackup") != "false",
    }
