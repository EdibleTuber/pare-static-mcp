from __future__ import annotations


def parse(apk) -> dict:
    """Parse AndroidManifest.xml and return a structured summary.

    Exported inference: a component is exported if android:exported is
    explicitly "true", OR (effective target SDK < 31 AND the component has
    at least one intent-filter AND android:exported is not explicitly "false").
    This mirrors Android's pre-31 implicit-export rule.

    Implementation: iterates manifest elements directly via apk.find_tags(kind)
    and reads attributes via apk.get_value_from_tag(elem, attr). This avoids
    the formatted-name round-trip bug in get_attribute_value(kind, attr, name=n)
    where androguard's is_tag_matched does not apply _format_value, causing
    None returns for APKs with short-form component names (e.g. ".Foo").

    androguard 4.1.3: find_tags returns lxml.etree._Element objects;
    get_value_from_tag reads the android:-namespaced attribute from a specific
    element. Intent-filter children appear as bare "intent-filter" child tags.
    """
    target = apk.get_effective_target_sdk_version()
    activities = apk.get_activities()
    services = apk.get_services()
    receivers = apk.get_receivers()
    providers = apk.get_providers()

    exported: list[str] = []
    for kind, formatted_names in (
        ("activity", activities),
        ("service", services),
        ("receiver", receivers),
        ("provider", providers),
    ):
        for elem in apk.find_tags(kind):
            raw_name = apk.get_value_from_tag(elem, "name")
            exp_val = apk.get_value_from_tag(elem, "exported")
            has_intent_filter = any(
                child.tag == "intent-filter" for child in elem
            )
            is_exp = exp_val == "true" or (
                target < 31 and has_intent_filter and exp_val != "false"
            )
            if is_exp:
                # Map raw element name back to the formatted name returned by
                # get_<kind>s() so the exported list is consistent with the
                # other returned lists.  Handles short-form names (.Foo →
                # com.pkg.Foo) via the endswith check.
                matched = next(
                    (fn for fn in formatted_names
                     if fn == raw_name or fn.endswith(raw_name)),
                    raw_name,
                )
                exported.append(matched)

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
