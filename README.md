![Tests](https://github.com/Nebulock-Inc/pySigma-pipeline-macos/actions/workflows/test.yml/badge.svg)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma macOS Processing Pipelines

This package adds pySigma processing pipelines for Sigma rules with `product: macos`. It provides the namespace `sigma.pipelines.macos` and a `pipelines` dictionary, which is how sigma-cli discovers plugin pipelines.

Rules select macOS telemetry through the logsource:

* `product: macos` with a `category` such as `process_creation` (optionally `service: endpointsecurity`) is Endpoint Security Framework (ESF) data.
* `product: macos` with `service: unifiedlog` is Unified Log data. The category narrows which log lines are in scope (for example `sudo`, `tcc`, `gatekeeper`, `mdm`).

Logsource values must be lowercase. A macOS rule with a wrong-case value fails conversion with a clear error instead of being silently skipped.

## Install

    pip install pySigma-pipeline-macos

With sigma-cli:

    sigma plugin install macos
    sigma list pipelines

(`sigma plugin install` works once the plugin is listed in the pySigma plugin directory. Until then, use `pip install` into the same environment as sigma-cli.)

## Pipelines

| Pipeline | Targets | Notes |
|---|---|---|
| `macos_esf_ecs` | ECS documents built from Endpoint Security events | Supports the 22 ESF categories in `sigma/pipelines/macos/taxonomy.py` (`process_creation`, `file_event`, `tcc_modification`, `sudo`, ...). Sigma fields are mapped to ECS field names; the logsource is replaced by ECS `event.*` conditions. |
| `macos_ul_ecs` | ECS documents built from Unified Log entries | Supports the 10 Unified Log categories in the taxonomy. Adds the subsystem / process predicate for the category and maps fields to ECS names. |
| `macos_ul_raw` | Native `log --style ndjson` keys (`subsystem`, `processImagePath`, `eventMessage`, ...) | Same categories as `macos_ul_ecs`, with the native key names. |
| `macos_falcon` | CrowdStrike Falcon (FDR / LogScale) | `process_creation` only. See Limitations. |

Events are expected to have the field names the taxonomy defines. This package does not collect telemetry.

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
print(LuceneBackend(processing_pipeline=pipelines["macos_esf_ecs"]).convert(rule)[0])
```

    (event.category:process AND event.type:start) AND (process.executable:*\/curl AND process.command_line:*\/tmp\/*)

The same rule with `macos_falcon` and the LogScale backend:

    event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=/^Mac$/i ImageFileName=/\/curl$/i CommandLine=/\/tmp\//i

Unified Log, with `service: unifiedlog`, `category: sudo` and `eventMessage|contains: COMMAND=`:

    # macos_ul_ecs (Lucene)
    process.executable:\/usr\/bin\/sudo AND message:*COMMAND\=*
    # macos_ul_raw (Lucene)
    processImagePath:\/usr\/bin\/sudo AND eventMessage:*COMMAND\=*

sigma-cli:

    sigma convert -t lucene -p macos_esf_ecs rule.yml
    sigma convert -t splunk -p macos_ul_raw rule.yml

## Limitations

* **Falcon is `process_creation` only.** `macos_falcon` converts `Image`, `CommandLine` and `ParentImage` for `process_creation` rules. Every other macOS category, and all `unifiedlog` rules, fail with "not supported on Falcon macOS telemetry". Fields without a Falcon equivalent (for example `SigningID`) also fail rather than being dropped.
* **No Kusto pipeline.** Microsoft Sentinel and Defender for Endpoint (Kusto) have no macOS tables for ESF or Unified Log data. Defender for Endpoint's `DeviceProcessEvents` carries macOS `process_creation`, and the stock `microsoft_xdr_pipeline` from pySigma-backend-kusto already converts those rules (covered by a test here); this package adds nothing for Kusto.
* **ES|QL matching is case-sensitive.** With pySigma-backend-elasticsearch 2.1.0 the ES|QL backend emits case-sensitive comparisons, unlike Sigma's default. Use the Lucene or EQL backend where case-insensitive matching matters.
* **Unified Log `launchd` events** are in the category table, but `log stream` does not deliver `/sbin/launchd` lines, so rules in that category cannot be matched against live-streamed data.
* **ESF only has a `macos_esf_ecs` pipeline.** There is no raw ESF pipeline; raw `eslogger` JSON is not mapped.
* Only the backends exercised by the tests are known to work: Elasticsearch (Lucene, EQL, ES|QL), Splunk and CrowdStrike LogScale. <!-- TASK16: link the support matrix here -->

## Development

    python -m venv .venv && . .venv/bin/activate
    pip install . pytest pysigma-backend-elasticsearch pysigma-backend-splunk pysigma-backend-crowdstrike pysigma-backend-kusto
    pytest

or `poetry install && poetry run pytest`. Code is formatted with `black` (line length 120).

## License

MIT. See `LICENSE`.
