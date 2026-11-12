![Tests](https://github.com/Nebulock-Inc/pySigma-pipeline-macos/actions/workflows/test.yml/badge.svg)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma macOS Processing Pipelines

This package adds pySigma processing pipelines for Sigma rules with `product: macos`. It provides the namespace `sigma.pipelines.macos`. pySigma discovers the module-level factory functions (`macos_esf_ecs`, `macos_ul_ecs`, `macos_ul_raw`, `macos_falcon`); the `pipelines` dictionary maps the same names to those factories, so call the entry to get a new pipeline: `pipelines["macos_esf_ecs"]()`.

Rules select macOS telemetry through the logsource:

* `product: macos` with a `category` such as `process_creation` (optionally `service: endpointsecurity`) is Endpoint Security Framework (ESF) data.
* `product: macos` with `service: unifiedlog` is Unified Log data. The category narrows which log lines are in scope (for example `sudo`, `tcc`, `gatekeeper`, `mdm`).

`process_creation` is scoped to the `exec` event (`event.action: exec`), so it does not match other process events. Logsource values must be lowercase, and a macOS rule whose `service` is anything other than `endpointsecurity` or `unifiedlog` (a misspelling such as `unifiedlogs`) fails conversion instead of being converted unscoped. A wrong-case value fails conversion with a clear error instead of being silently skipped.

Each pipeline scopes only its own family. A Unified Log pipeline run alone passes an ESF rule through unscoped and unmapped, and the ESF pipeline does the same for a Unified Log rule. Stack both pipelines (for example `-p macos_esf_ecs -p macos_ul_ecs`), or use the one that matches the rule's service.

## Install

    pip install pySigma-pipeline-macos

With sigma-cli:

    sigma plugin install macos
    sigma list pipelines

(`sigma plugin install` works once the plugin is listed in the pySigma plugin directory. Until then, use `pip install` into the same environment as sigma-cli.)

## Pipelines

| Pipeline | Targets | Notes |
|---|---|---|
| `macos_esf_ecs` | ECS documents built from Endpoint Security events | Supports the 22 ESF categories in `sigma/pipelines/macos/taxonomy.py` (`process_creation`, `file_event`, `tcc_modification`, `sudo`, ...). Sigma fields are mapped to ECS field names; the logsource is replaced by ECS `event.*` conditions. `file_event` covers file creates and the destination of renames. `file_attribute_change` is scoped on the ESF event names (`setextattr`, `deleteextattr`, `setmode`, `setowner`, `setflags`). `privilege_change` includes `setegid` and `setregid`, and `user_account_change` covers the `od_*` user and group events (including disable, enable, remove and set). |
| `macos_ul_ecs` | ECS documents built from Unified Log entries by the coreSigma collector | Supports the 10 Unified Log categories in the taxonomy. Adds the subsystem / process predicate for the category and maps fields to the collector's names (`unified_log.subsystem`, `unified_log.sender_image_path`, `log.level`, ...). Elastic's macOS Unified Logs integration names two fields differently (`dll.path`, `unified_log.message_type`); there is no pySigma pipeline for that integration yet. |
| `macos_ul_raw` | Native `log --style ndjson` keys (`subsystem`, `processImagePath`, `eventMessage`, ...) | Same categories as `macos_ul_ecs`, with the native key names. |
| `macos_falcon` | CrowdStrike Falcon LogScale | `process_creation` only. See Limitations. |

Events are expected to have the field names the taxonomy defines. This package does not collect telemetry.

Field checks: `macos_falcon` also fails unknown fields in correlation group-by, aliases and condition fields, and in a correlation rule's own `fields:` (a base rule's own `fields:` is not checked, because LogScale ignores it). The ESF and Unified Log pipelines fail a rule that uses a field the taxonomy does not know, in a detection item, in a `fields:` list, in a correlation's group-by, and in a correlation's condition field. Known fields are not checked per category: a known field is accepted in any ESF category, even where those events never carry it (for example `TargetUser` in `privilege_change`, or `Success` in `process_creation`), and the query then simply never matches. `process.pid` and `process.parent.pid` values are emitted as strings, which matches keyword-mapped pid fields. Elastic Defend's long-typed pid fields are not supported in this release. `user.id` and similar id fields are keywords: plain values are converted to strings, and numeric comparisons (`gt`, `lt`, ...) on them fail instead of comparing a keyword with a number.

The `ecs_macos_esf` pipeline in pySigma-backend-elasticsearch is a different, Elasticsearch-specific pipeline. `macos_esf_ecs` is the multi-backend layer: it scopes rules by ESF event name and category and is tested with the Lucene, EQL, ES|QL, Splunk and LogScale backends. A fixed `ecs_macos_esf` will be proposed upstream separately, once it has been tested against live Elastic Defend data.

## Examples

Python:

```python
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.macos import pipelines

rule = SigmaCollection.from_yaml("""
title: Curl writing to /tmp
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: /curl
        CommandLine|contains: /tmp/
    condition: selection
""")
print(LuceneBackend(processing_pipeline=pipelines["macos_esf_ecs"]()).convert(rule)[0])
```

    (event.category:process AND event.type:start AND event.action:exec) AND (process.executable:*\/curl AND process.command_line:*\/tmp\/*)

The same rule with `macos_falcon` and the LogScale backend:

    #event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=/^Mac$/i ImageFileName=/\/curl$/i CommandLine=/\/tmp\//i

Unified Log, with `service: unifiedlog`, `category: sudo` and `eventMessage|contains: COMMAND=`:

    # macos_ul_ecs (Lucene)
    process.executable:\/usr\/bin\/sudo AND message:*COMMAND\=*
    # macos_ul_raw (Lucene)
    processImagePath:\/usr\/bin\/sudo AND eventMessage:*COMMAND\=*

sigma-cli:

    sigma convert -t lucene -p macos_esf_ecs rule.yml
    sigma convert -t splunk -p macos_ul_raw rule.yml

## Fields for account, authentication and policy categories

Besides the process fields (`Image`, `CommandLine`, `User`, `UserId`, ...), these categories have fields of their own. All map to ECS or ECS-style names; see `ESF_FIELDS` in `taxonomy.py` for the exact keys.

| Category | Sigma fields |
|---|---|
| `authentication` | `TargetUser` and `InstigatorImage` (both Open Directory logins only), `Success`, `AuthenticationType` |
| `sudo` (events `sudo` and `su`) | `SourceUser`, `TargetUser`, `TargetUserId`, `TargetImage` (sudo: the command run; su: the login shell), `Success`, `FailureReason` |
| `screen_sharing` | `TargetUser` (the account used to authenticate; empty for VNC-password sessions), `Success`, `SourceAddress`, `ViewerAppleID`, `ExistingSession` |
| `configuration_profile` | `ProfileIdentifier`, `ProfileDisplayName`, `ProfileInstallSource`, `ProfileScope`, `InstigatorImage` |
| `xprotect` | `MalwareIdentifier`, `MalwareIncidentIdentifier`, `RemediationAction`, `TargetFilename`, `Success` (remediation only) |
| `gatekeeper_override` | `TargetFilename`, `FileSha256`, `FileSigningID`, `FileTeamID` |
| `user_account_change` | `TargetUser`, `TargetGroup`, `OdAttributeName`, `OdAttributeValue`, `Success`, `InstigatorImage` |

`Success` is a boolean in Sigma: `true` converts to `event.outcome: success` and `false` to `event.outcome: failure`; any other value fails conversion. `setowner` and `setflags` in `file_attribute_change` also expose the target path as `TargetFilename`.

For `od_group_add` and `od_group_remove`, `TargetUser` is the member value, which can be a user name, a user UUID or a group UUID. The member type (not mapped) says which.

The `xprotect` and `gatekeeper_override` fields come from the member names in Apple's Endpoint Security headers; those events were not observed in captures, so treat them as unverified against live data.

## Limitations

* **Falcon is `process_creation` only, with no keyword search.** Keyword (field-less) detection items fail with a clear message. `macos_falcon` converts `Image`, `CommandLine` and `ParentImage` for `process_creation` rules. Every other macOS category, and all `unifiedlog` rules, fail with "not supported on Falcon macOS telemetry". Fields without a Falcon equivalent (for example `SigningID`) also fail rather than being dropped. `ParentImage` is matched on the parent's basename only (Falcon's `ParentBaseFileName`), so only exact and `endswith` values with a non-empty basename are accepted; `contains`, `startswith` and `re` fail.
* **Falcon LogScale only.** `macos_falcon` scopes on the LogScale tag `#event_simpleName`. Falcon Data Replicator (FDR) data outside LogScale, for example FDR shipped to Splunk, names that field `event_simpleName` (no `#`), so these queries never match there.
* **No Kusto pipeline.** Microsoft Sentinel and Defender for Endpoint (Kusto) have no macOS tables for ESF or Unified Log data. Defender for Endpoint's `DeviceProcessEvents` carries macOS `process_creation`, and the stock `microsoft_xdr_pipeline` from pySigma-backend-kusto already converts those rules (covered by a test here); this package adds nothing for Kusto.
* **Rename coverage depends on the data source.** `file_event` matches creates by `event.type` and renames by `event.action: rename`. Whether a rename reaches your index with those values (and with the destination path in `TargetFilename`) depends on the collector or integration that produced the documents; check your data before relying on rename rules.
* **`eventType` is raw-only.** The native Unified Log key `eventType` works with `macos_ul_raw`; `macos_ul_ecs` fails it because ECS Unified Log documents do not carry it. Unknown fields fail in both Unified Log pipelines.
* **ES|QL matching is case-sensitive.** With pySigma-backend-elasticsearch 2.1.0 the ES|QL backend emits case-sensitive comparisons, unlike Sigma's default. Use the Lucene or EQL backend where case-insensitive matching matters.
* **Unified Log `launchd` scoping** matches `processImagePath = /sbin/launchd` (exact path); the pipeline adds no other condition for that category.
* **ESF only has a `macos_esf_ecs` pipeline.** There is no raw ESF pipeline; raw `eslogger` JSON is not mapped.
* **LogScale has no correlation support.** LogScale (pySigma-backend-crowdstrike) does not convert correlation rules, so the Falcon correlation field checks only matter for other backends.
* Only the backends exercised by the tests are known to work: Elasticsearch (Lucene, EQL, ES|QL), Splunk and CrowdStrike LogScale. <!-- TASK16: link the support matrix here -->

## Tested versions

CI runs pySigma 1.x on Python 3.10 to 3.14, because the backends used by the tests still pin pySigma below 2. pySigma 2.x was tested locally only (the full suite passes with the backend packages installed without their dependency pins); it is not covered by CI.

## Development

    python -m venv .venv && . .venv/bin/activate
    pip install . pytest pysigma-backend-elasticsearch pysigma-backend-splunk pysigma-backend-crowdstrike pysigma-backend-kusto
    pytest

or `poetry install && poetry run pytest`. Code is formatted with `black` (line length 120).

## License

MIT. See `LICENSE`.
