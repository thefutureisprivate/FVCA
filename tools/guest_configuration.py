"""Encode the canonical resource settings shared by Host composition and review."""

import guest_boot_bundle


def settings_record(settings):
    if (
        not isinstance(settings, dict)
        or settings.keys() != {"schema", "guest", "configuration_revision", "vcpus", "memory_mib"}
        or settings["schema"] != "fvca-service-guest-vm-v2"
        or settings["guest"] != guest_boot_bundle.SERVICE_GUEST_ID
    ):
        raise ValueError("invalid Service Guest resource settings or Guest identity")
    revision, vcpus, memory = (settings[key] for key in ("configuration_revision", "vcpus", "memory_mib"))
    if type(revision) is not int or not 1 <= revision < 2**64:
        raise ValueError("invalid Service Guest configuration revision")
    if (type(vcpus) is not int or not 1 <= vcpus <= 4
            or type(memory) is not int or not 1024 <= memory <= 4096 or memory % 256):
        raise ValueError("Service Guest resources exceed the approved machine profile")
    return (f"FVCA-SERVICE-GUEST-VM-2\nguest={settings['guest']}\nrevision={revision}\n"
            f"vcpus={vcpus}\nmemory_mib={memory}\n").encode("ascii")
