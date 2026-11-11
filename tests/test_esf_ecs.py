"""Tests for the macos_esf_ecs pipeline."""

import pytest
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.elasticsearch.elasticsearch_eql import EqlBackend
from sigma.backends.elasticsearch.elasticsearch_esql import ESQLBackend
from sigma.exceptions import SigmaTransformationError

from sigma.pipelines.macos import pipelines
from sigma.pipelines.macos.taxonomy import ESF_CATEGORIES


def test_process_creation_eql():
    """A process_creation rule converts to EQL with the exact expected string."""
    rule = """
title: Test Process Creation
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: /curl
    condition: selection
"""
    backend = EqlBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    result = backend.convert(SigmaCollection.from_yaml(rule))[0]
    assert result == 'any where (event.category:"process" and event.type:"start") and process.executable:"*/curl"'


def test_unknown_category_fails():
    """A rule with network_connection category raises SigmaTransformationError."""
    rule = """
title: Test Unknown Category
logsource:
    product: macos
    category: network_connection
detection:
    selection:
        DestinationPort: 443
    condition: selection
"""
    backend = EqlBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    with pytest.raises(SigmaTransformationError, match="not supported"):
        backend.convert(SigmaCollection.from_yaml(rule))


def test_userid_string():
    """UserId field converts to string type for both Lucene and ES|QL."""
    rule = """
title: Test UserId String
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        UserId: 0
    condition: selection
"""
    # Test Lucene
    lucene_backend = LuceneBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    lucene_result = lucene_backend.convert(SigmaCollection.from_yaml(rule))[0]
    assert lucene_result == "(event.category:process AND event.type:start) AND user.id:0"

    # Test ES|QL - contains check for string conversion
    esql_backend = ESQLBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    esql_result = esql_backend.convert(SigmaCollection.from_yaml(rule))[0]
    assert 'user.id=="0"' in esql_result


def test_service_unifiedlog_untouched():
    """A rule with service: unifiedlog is not scoped by this pipeline."""
    rule = """
title: Test Unified Log
logsource:
    product: macos
    service: unifiedlog
    category: tcc
detection:
    selection:
        Image: /usr/bin/test
        UserId: 0
    condition: selection
"""
    backend = EqlBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    result = backend.convert(SigmaCollection.from_yaml(rule))[0]

    # UL rules should keep raw Sigma field names (no ECS mapping)
    assert "Image" in result
    assert "UserId" in result
    assert "process.executable" not in result  # Should NOT be mapped
    assert "user.id" not in result  # Should NOT be mapped

    # No category conditions should be added
    assert "event.category" not in result
    assert "event.type" not in result

    # No string conversion (UserId should stay numeric)
    assert "UserId:0" in result or 'UserId:"0"' not in result


def test_no_caseless():
    """No converted query contains .caseless."""
    # Test a sample rule from each category
    for category in ESF_CATEGORIES:
        rule = f"""
title: Test {category}
logsource:
    product: macos
    category: {category}
detection:
    selection:
        Image|endswith: /test
    condition: selection
"""
        backend = EqlBackend(processing_pipeline=pipelines["macos_esf_ecs"])
        result = backend.convert(SigmaCollection.from_yaml(rule))[0]
        assert ".caseless" not in result, f"Category '{category}' produced .caseless in query: {result}"


def test_unmapped_field_fails():
    """A rule using an unmapped Sigma field raises SigmaTransformationError."""
    rule = """
title: Test Unmapped Field
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        DestinationHostname: evil.com
    condition: selection
"""
    backend = EqlBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    with pytest.raises(SigmaTransformationError, match="not supported"):
        backend.convert(SigmaCollection.from_yaml(rule))


def test_target_group_and_kext_fields():
    """TargetGroupId is a string user.target.group.id, as TargetUserId is; KextIdentifier is kext.identifier."""
    rule = """
title: t
logsource: {product: macos, category: privilege_change}
detection:
    selection:
        TargetGroupId: 0
    condition: selection
"""
    esql = ESQLBackend(processing_pipeline=pipelines["macos_esf_ecs"]).convert(SigmaCollection.from_yaml(rule))[0]
    assert 'user.target.group.id=="0"' in esql
    kext = rule.replace("privilege_change", "driver_load").replace(
        "TargetGroupId: 0", "KextIdentifier|contains: rootkit"
    )
    lucene = LuceneBackend(processing_pipeline=pipelines["macos_esf_ecs"]).convert(SigmaCollection.from_yaml(kext))[0]
    assert lucene == "event.action:kextload AND kext.identifier:*rootkit*"


def test_user_userid_fields_work():
    """User and UserId fields (which have ecs but no raw) convert successfully."""
    rule = """
title: Test User Fields
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        User: root
        UserId: 0
    condition: selection
"""
    backend = EqlBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    result = backend.convert(SigmaCollection.from_yaml(rule))[0]
    # Both fields should be mapped to their ECS equivalents
    assert "user.name" in result
    assert "user.id" in result


def test_unknown_category_foo_fails():
    """A rule with an unknown category (not in ESF_CATEGORIES) raises SigmaTransformationError."""
    rule = """
title: Test Unknown Category Foo
logsource:
    product: macos
    category: foo
detection:
    selection:
        Image: /test
    condition: selection
"""
    backend = EqlBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    with pytest.raises(SigmaTransformationError, match="category 'foo' not supported"):
        backend.convert(SigmaCollection.from_yaml(rule))


def test_missing_category_fails():
    """A rule with no category raises SigmaTransformationError."""
    rule = """
title: Test Missing Category
logsource:
    product: macos
detection:
    selection:
        Image: /test
    condition: selection
"""
    backend = EqlBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    with pytest.raises(SigmaTransformationError, match="category missing; required for macOS ESF rules"):
        backend.convert(SigmaCollection.from_yaml(rule))


def test_unifiedlog_unknown_category_untouched():
    """A UL rule with an unknown category is not failed by this pipeline."""
    rule = """
title: Test UL Unknown Category
logsource:
    product: macos
    service: unifiedlog
    category: unknown_category
detection:
    selection:
        Image: /test
    condition: selection
"""
    backend = EqlBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    # Should not raise an error - UL rules are not scoped by this pipeline
    result = backend.convert(SigmaCollection.from_yaml(rule))[0]
    # Field should not be mapped
    assert "Image" in result


def test_windows_rule_untouched():
    """A Windows rule passes through with no error and no macOS transformations."""
    rule = """
title: Test Windows Rule
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image: test.exe
    condition: selection
"""
    backend = EqlBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    # Should not raise an error
    result = backend.convert(SigmaCollection.from_yaml(rule))[0]

    # Should keep original field name (no macOS field mapping)
    assert "Image" in result

    # Should NOT have macOS category conditions
    assert "event.category" not in result or "process" not in result


def test_linux_rule_untouched():
    """A Linux rule with no category passes through with no error."""
    rule = """
title: Test Linux Rule
logsource:
    product: linux
detection:
    selection:
        Image: /bin/test
    condition: selection
"""
    backend = EqlBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    # Should not raise an error (even without category)
    result = backend.convert(SigmaCollection.from_yaml(rule))[0]

    # Should keep original field name
    assert "Image" in result


@pytest.mark.parametrize(
    "logsource,message",
    [
        ("product: MacOS\n    category: process_creation", "logsource product 'MacOS' must be lowercase"),
        ("product: macos\n    category: Process_Creation", "logsource category 'Process_Creation' must be lowercase"),
        # LogsourceCondition compares service case-sensitively too; it only mapped via the service-less condition
        (
            "product: macos\n    service: EndpointSecurity\n    category: process_creation",
            "logsource service 'EndpointSecurity' must be lowercase",
        ),
    ],
)
def test_wrong_case_esf_logsource_fails(logsource, message):
    """Wrong-case ESF logsource values fail instead of converting without the ECS mapping."""
    rule = f"""
title: Test Wrong Case
logsource:
    {logsource}
detection:
    selection:
        Image: /test
    condition: selection
"""
    backend = EqlBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    with pytest.raises(SigmaTransformationError, match=message):
        backend.convert(SigmaCollection.from_yaml(rule))


def test_service_endpointsecurity_mixedcase_unknown_category():
    """A rule with service: EndpointSecurity (mixed case) and unknown category fails with category error."""
    rule = """
title: Test EndpointSecurity Mixed Case
logsource:
    product: macos
    service: EndpointSecurity
    category: foo
detection:
    selection:
        Image: /test
    condition: selection
"""
    backend = EqlBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    # Should recognize as ESF rule (case-insensitive) and fail with category error
    with pytest.raises(SigmaTransformationError, match="category 'foo' not supported"):
        backend.convert(SigmaCollection.from_yaml(rule))


@pytest.mark.parametrize(
    "service,category",
    [
        ("unifiedlog", "sudo"),  # category shared with ESF_CATEGORIES
        ("unifiedlog", "xprotect"),  # category shared with ESF_CATEGORIES
        ("UnifiedLog", "process_creation"),
        ("foo", "process_creation"),
    ],
)
def test_non_esf_service_untouched(service, category):
    """Only no service or service: endpointsecurity is ESF; other services get no ESF condition, mapping or failure."""
    rule = f"""
title: Test Non-ESF Service
logsource:
    product: macos
    service: {service}
    category: {category}
detection:
    selection:
        Image: /test
        UserId: 0
        subsystem: com.apple.test
    condition: selection
"""
    expected = EqlBackend().convert(SigmaCollection.from_yaml(rule))
    backend = EqlBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    assert backend.convert(SigmaCollection.from_yaml(rule)) == expected


def test_correlation_group_by_mapped():
    """A Splunk event_count correlation over a macOS rule converts, with group-by User mapped to user.name."""
    from sigma.backends.splunk import SplunkBackend

    rules = """
title: Curl
name: macos_curl
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        Image|endswith: /curl
    condition: selection
---
title: Many Curl
correlation:
    type: event_count
    rules: macos_curl
    group-by: User
    timespan: 5m
    condition:
        gte: 10
"""
    backend = SplunkBackend(processing_pipeline=pipelines["macos_esf_ecs"])
    assert backend.convert(SigmaCollection.from_yaml(rules)) == [
        'event.category="process" event.type="start" process.executable="*/curl"\n\n'
        "| bin _time span=5m\n| stats count as event_count by _time user.name\n\n| search event_count >= 10"
    ]
