"""macOS taxonomy - single source of truth for categories and field mappings."""

from __future__ import annotations  # keeps annotations lazy; the table is plain dataclasses and does not import pySigma

from dataclasses import dataclass


@dataclass
class EsfCategory:
    events: tuple[str, ...]
    ecs: dict[str, str]


@dataclass
class UlCategory:
    raw: list[tuple[str, str, str]]


@dataclass
class EsfField:
    raw: dict[str, str | list[str]]
    ecs: str | list[str]


@dataclass
class UlField:
    raw: str
    ecs: str


ESF_CATEGORIES: dict[str, EsfCategory] = {
    "process_creation": EsfCategory(events=("exec",), ecs={"event.category": "process", "event.type": "start"}),
    "file_event": EsfCategory(events=("create",), ecs={"event.category": "file", "event.type": "creation"}),
    "file_delete": EsfCategory(events=("unlink",), ecs={"event.category": "file", "event.type": "deletion"}),
    "file_rename": EsfCategory(events=("rename",), ecs={"event.category": "file", "event.action": "rename"}),
    "file_access": EsfCategory(events=("open",), ecs={"event.category": "file", "event.action": "open"}),
    "file_attribute_change": EsfCategory(
        events=("setextattr", "deleteextattr", "setmode", "setowner", "setflags"),
        ecs={"event.category": "file", "event.type": "change"},
    ),
    "process_access": EsfCategory(
        events=("get_task", "trace"), ecs={"event.category": "process", "event.action": ("get_task", "trace")}
    ),
    "create_remote_thread": EsfCategory(events=("remote_thread_create",), ecs={"event.action": "remote_thread_create"}),
    "process_signal": EsfCategory(events=("signal",), ecs={"event.action": "signal"}),
    "memory_protection": EsfCategory(events=("mprotect",), ecs={"event.action": "mprotect"}),
    "driver_load": EsfCategory(events=("kextload",), ecs={"event.action": "kextload"}),
    "xpc_connection": EsfCategory(events=("xpc_connect",), ecs={"event.action": "xpc_connect"}),
    "tcc_modification": EsfCategory(events=("tcc_modify",), ecs={"event.action": "tcc_modify"}),
    "background_task": EsfCategory(
        events=("btm_launch_item_add", "btm_launch_item_remove"),
        ecs={"event.action": ("btm_launch_item_add", "btm_launch_item_remove")},
    ),
    "privilege_change": EsfCategory(
        events=("setuid", "setgid", "seteuid", "setreuid"),
        ecs={"event.action": ("setuid", "setgid", "seteuid", "setreuid")},
    ),
    "authentication": EsfCategory(events=("authentication",), ecs={"event.category": "authentication"}),
    "gatekeeper_override": EsfCategory(
        events=("gatekeeper_user_override",), ecs={"event.action": "gatekeeper_user_override"}
    ),
    "configuration_profile": EsfCategory(
        events=("profile_add", "profile_remove"), ecs={"event.action": ("profile_add", "profile_remove")}
    ),
    "screen_sharing": EsfCategory(
        events=("screensharing_attach", "screensharing_detach"),
        ecs={"event.action": ("screensharing_attach", "screensharing_detach")},
    ),
    "user_account_change": EsfCategory(
        events=(
            "od_create_user",
            "od_delete_user",
            "od_modify_password",
            "od_attribute_value_add",
            "od_group_add",
            "od_create_group",
        ),
        ecs={
            "event.category": "iam",
            "event.action": (
                "od_create_user",
                "od_delete_user",
                "od_modify_password",
                "od_attribute_value_add",
                "od_group_add",
                "od_create_group",
            ),
        },
    ),
    "sudo": EsfCategory(events=("sudo", "su"), ecs={"event.action": ("sudo", "su")}),
    "xprotect": EsfCategory(
        events=("xp_malware_detected", "xp_malware_remediated"),
        ecs={"event.action": ("xp_malware_detected", "xp_malware_remediated")},
    ),
}

ESF_FIELDS: dict[str, EsfField] = {
    "Image": EsfField(
        raw={"exec": "event.exec.target.executable.path", "*": "process.executable.path"}, ecs="process.executable"
    ),
    "CommandLine": EsfField(raw={"exec": "event.exec.args"}, ecs="process.command_line"),
    "ParentImage": EsfField(raw={"exec": "process.executable.path"}, ecs="process.parent.executable"),
    "ProcessId": EsfField(raw={"exec": "process.audit_token.pid", "*": "process.audit_token.pid"}, ecs="process.pid"),
    "ParentProcessId": EsfField(raw={"exec": "process.ppid", "*": "process.ppid"}, ecs="process.parent.pid"),
    "SigningID": EsfField(
        raw={"exec": "event.exec.target.signing_id", "*": "process.signing_id"}, ecs="process.code_signature.signing_id"
    ),
    "TeamID": EsfField(
        raw={"exec": "event.exec.target.team_id", "*": "process.team_id"}, ecs="process.code_signature.team_id"
    ),
    "TargetFilename": EsfField(
        raw={
            "create": ["event.create.destination.existing_file.path", "event.create.destination.new_path.filename"],
            "unlink": "event.unlink.target.path",
            "open": "event.open.file.path",
            "rename": ["event.rename.destination.existing_file.path", "event.rename.destination.new_path.filename"],
            "setextattr": "event.setextattr.target.path",
            "deleteextattr": "event.deleteextattr.target.path",
            "setmode": "event.setmode.target.path",
        },
        ecs="file.path",
    ),
    "SourceFilename": EsfField(raw={"rename": "event.rename.source.path"}, ecs="file.Ext.original.path"),
    "TargetDirectory": EsfField(
        raw={
            "create": "event.create.destination.new_path.dir.path",
            "rename": "event.rename.destination.new_path.dir.path",
        },
        ecs="file.directory",
    ),
    "ExtendedAttribute": EsfField(
        raw={"setextattr": "event.setextattr.extattr", "deleteextattr": "event.deleteextattr.extattr"},
        ecs="file.Ext.extattr",
    ),
    "TargetImage": EsfField(
        raw={"signal": "event.signal.target.executable.path", "get_task": "event.get_task.target.executable.path"},
        ecs="Target.process.executable",
    ),
    "SignalNumber": EsfField(raw={"signal": "event.signal.sig"}, ecs="signal.number"),
    "MemoryProtection": EsfField(raw={"mprotect": "event.mprotect.protection"}, ecs="memory.protection"),
    "XpcServiceName": EsfField(raw={"xpc_connect": "event.xpc_connect.service_name"}, ecs="xpc.service_name"),
    "TccService": EsfField(raw={"tcc_modify": "event.tcc_modify.service"}, ecs="tcc.service"),
    "TccIdentity": EsfField(raw={"tcc_modify": "event.tcc_modify.identity"}, ecs="tcc.identity"),
    "TccRight": EsfField(raw={"tcc_modify": "event.tcc_modify.right"}, ecs="tcc.right"),
    "TccReason": EsfField(raw={"tcc_modify": "event.tcc_modify.reason"}, ecs="tcc.reason"),
    "InstigatorImage": EsfField(
        raw={
            "tcc_modify": "event.tcc_modify.instigator.executable.path",
            "btm_launch_item_add": "event.btm_launch_item_add.instigator.executable.path",
            "btm_launch_item_remove": "event.btm_launch_item_remove.instigator.executable.path",
        },
        ecs="process.parent.executable",
    ),
    "BtmItemUrl": EsfField(raw={"btm_launch_item_add": "event.btm_launch_item_add.item.item_url"}, ecs="btm.item.url"),
    "BtmItemType": EsfField(
        raw={"btm_launch_item_add": "event.btm_launch_item_add.item.item_type"}, ecs="btm.item.type"
    ),
    "BtmExecutable": EsfField(
        raw={"btm_launch_item_add": "event.btm_launch_item_add.executable_path"}, ecs="btm.executable_path"
    ),
    "TargetUserId": EsfField(raw={"setuid": "event.setuid.uid"}, ecs="user.target.id"),
    "TargetGroupId": EsfField(raw={"setgid": "event.setgid.gid"}, ecs="user.target.group.id"),
    "KextIdentifier": EsfField(raw={"kextload": "event.kextload.identifier"}, ecs="kext.identifier"),
    "User": EsfField(raw={}, ecs="user.name"),
    "UserId": EsfField(raw={}, ecs="user.id"),
    "Signed": EsfField(raw={}, ecs="process.code_signature.exists"),
    "Trusted": EsfField(raw={}, ecs="process.code_signature.trusted"),
}

# Unified Log category predicates: (field, modifier, value) tuples, ORed within a category.
# Modifier spellings used below, with Sigma semantics (string matching is case-insensitive
# unless the modifier carries "|cased"):
#   "="           exact match           (Sigma: field: value)
#   "startswith"  prefix match          (Sigma: field|startswith: value)
#   "endswith"    suffix match          (Sigma: field|endswith: value)
# No predicate needs "|cased": subsystem identifiers and image paths are matched the same
# whatever their case (APFS is case-insensitive by default), including xprotect, which is
# case-insensitive too. If one ever does, spell it "startswith|cased", "=|cased" or
# "endswith|cased". Consumers that build NSPredicate filters from this table must therefore
# use case-insensitive comparisons ([c]).
# Other table semantics: a tuple of values in an ESF ecs condition means "any of", and a list of
# raw paths in ESF_FIELDS means "any of these paths".
UL_CATEGORIES: dict[str, UlCategory] = {
    "tcc": UlCategory(raw=[("subsystem", "startswith", "com.apple.TCC")]),
    "authorization": UlCategory(raw=[("subsystem", "=", "com.apple.Authorization")]),
    "sudo": UlCategory(raw=[("processImagePath", "=", "/usr/bin/sudo")]),
    "firewall": UlCategory(raw=[("subsystem", "startswith", "com.apple.ALF")]),
    "gatekeeper": UlCategory(
        raw=[("subsystem", "startswith", "com.apple.syspolicy"), ("processImagePath", "=", "/usr/libexec/syspolicyd")]
    ),
    "launchd": UlCategory(raw=[("processImagePath", "=", "/sbin/launchd")]),
    "xprotect": UlCategory(raw=[("subsystem", "startswith", "com.apple.xprotect")]),
    "securityd": UlCategory(raw=[("subsystem", "=", "com.apple.securityd")]),
    "opendirectory": UlCategory(raw=[("subsystem", "startswith", "com.apple.opendirectoryd")]),
    "mdm": UlCategory(raw=[("processImagePath", "endswith", "/mdmclient")]),
}

# Aliases (message, Message, Image) map to the native ndjson key in raw; `log` emits no such keys.
UL_FIELDS: dict[str, UlField] = {
    "subsystem": UlField(raw="subsystem", ecs="unified_log.subsystem"),
    "category": UlField(raw="category", ecs="unified_log.category"),
    "eventMessage": UlField(raw="eventMessage", ecs="message"),
    "message": UlField(raw="eventMessage", ecs="message"),
    "Message": UlField(raw="eventMessage", ecs="message"),
    "processImagePath": UlField(raw="processImagePath", ecs="process.executable"),
    "Image": UlField(raw="processImagePath", ecs="process.executable"),
    "senderImagePath": UlField(raw="senderImagePath", ecs="unified_log.sender_image_path"),
    "messageType": UlField(raw="messageType", ecs="log.level"),
    "processID": UlField(raw="processID", ecs="process.pid"),
    "userID": UlField(raw="userID", ecs="user.id"),
}
