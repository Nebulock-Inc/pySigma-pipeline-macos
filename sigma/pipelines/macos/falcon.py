"""macOS pipeline for CrowdStrike Falcon LogScale (FDR telemetry)."""

from dataclasses import dataclass

from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions import IncludeFieldCondition, IsSigmaCorrelationRuleCondition, RuleProcessingCondition
from sigma.processing.transformations.base import DetectionItemTransformation
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.exceptions import SigmaTransformationError
from sigma.modifiers import SigmaEndswithModifier
from sigma.processing.transformations import (
    AddConditionTransformation,
    DetectionItemFailureTransformation,
    FieldMappingTransformation,
    ReplaceStringTransformation,
    RuleFailureTransformation,
    Transformation,
)
from sigma.rule import SigmaRule

from .esf import FieldNameCheck, MacOSESFCondition, UnknownFieldCondition, require_lowercase_logsource

FIELDS = {"Image": "ImageFileName", "CommandLine": "CommandLine", "ParentImage": "ParentBaseFileName"}


@dataclass
class FalconUnsupportedMacOSCondition(RuleProcessingCondition):
    """Any macOS rule except ESF-scoped process_creation (this includes unifiedlog)."""

    def match(self, rule) -> bool:
        if isinstance(rule, SigmaCorrelationRule):
            return False  # its referenced rules fail on their own
        return rule.logsource.product == "macos" and not MacOSESFCondition("process_creation").match(rule)


class FalconLowercaseLogsourceCheck(Transformation):
    """Fail wrong-case macOS logsource values, which the exact-match conditions would skip."""

    def apply(self, rule) -> None:
        if isinstance(rule, SigmaRule) and (rule.logsource.product or "").lower() == "macos":
            require_lowercase_logsource(rule, "Falcon macOS")


class FalconKeywordGuard(DetectionItemTransformation):
    """Fail keyword items clearly instead of as an unknown field."""

    def apply_detection_item(self, detection_item) -> None:
        if detection_item.field is None:
            raise SigmaTransformationError(
                "keyword search isn't supported for Falcon macOS process_creation", source=detection_item.source
            )


class FalconParentImageGuard(DetectionItemTransformation):
    """Allow only exact and endswith ParentImage values with a non-empty basename.

    ParentBaseFileName holds just the basename, so contains/startswith/re (and a value
    that is all directory) can't be expressed after the basename strip.
    """

    def apply_detection_item(self, detection_item) -> None:
        mods = [m.__name__ for m in detection_item.modifiers if m is not SigmaEndswithModifier]
        if mods:
            raise SigmaTransformationError(
                f"ParentImage modifier(s) {mods} not supported on Falcon macOS telemetry "
                "(ParentBaseFileName is a basename; only exact and endswith values work)",
                source=detection_item.source,
            )
        for value in detection_item.value:
            if not str(value).rsplit("/", 1)[-1].strip("*?"):
                raise SigmaTransformationError(
                    f"ParentImage value '{value}' has an empty or wildcard-only basename; not supported on Falcon macOS telemetry",
                    source=detection_item.source,
                )


def macos_falcon() -> ProcessingPipeline:
    """Pipeline for macOS process_creation rules on Falcon LogScale (FDR)."""

    def scope():
        return [MacOSESFCondition("process_creation")]

    return ProcessingPipeline(
        name="macos_falcon",
        priority=20,
        items=[
            ProcessingItem(
                identifier="macos_falcon_lowercase_logsource", transformation=FalconLowercaseLogsourceCheck()
            ),
            ProcessingItem(
                identifier="macos_falcon_unsupported_rule",
                transformation=RuleFailureTransformation("not supported on Falcon macOS telemetry"),
                rule_conditions=[FalconUnsupportedMacOSCondition()],
            ),
            ProcessingItem(
                identifier="macos_falcon_keyword_failure",
                transformation=FalconKeywordGuard(),
                rule_conditions=scope(),
            ),
            ProcessingItem(
                identifier="macos_falcon_unmapped_field_failure",
                transformation=DetectionItemFailureTransformation("Field not supported on Falcon macOS telemetry"),
                rule_conditions=scope(),
                field_name_conditions=[UnknownFieldCondition(list(FIELDS))],
            ),
            ProcessingItem(
                identifier="macos_falcon_field_name_check",
                # no host field is mapped, so nothing passes besides the mapping's names
                transformation=FieldNameCheck("Falcon macOS", FIELDS, scope()[0], extra=()),
                # shortcut: correlations only; LogScaleBackend 3.0.0 ignores a rule's fields: (12 shipped rules list
                # ProcessId, ParentProcessId or User), check them too if a Falcon backend starts emitting fields:
                rule_conditions=[*scope(), IsSigmaCorrelationRuleCondition()],
            ),
            ProcessingItem(
                identifier="macos_falcon_parent_guard",
                transformation=FalconParentImageGuard(),
                rule_conditions=scope(),
                field_name_conditions=[IncludeFieldCondition(["ParentImage"])],
            ),
            # Falcon exposes only the parent's basename.
            ProcessingItem(
                identifier="macos_falcon_parent_basename",
                transformation=ReplaceStringTransformation(regex=r"^.*/", replacement=""),
                rule_conditions=scope(),
                field_name_conditions=[IncludeFieldCondition(["ParentImage"])],
            ),
            ProcessingItem(
                identifier="macos_falcon_scope",
                transformation=AddConditionTransformation(
                    {"#event_simpleName|re": "^(ProcessRollup2|SyntheticProcessRollup2)$", "event_platform": "Mac"}  # a tag in LogScale: event_simpleName (no #) matches nothing
                ),
                rule_conditions=scope(),
            ),
            ProcessingItem(
                identifier="macos_falcon_field_mapping",
                transformation=FieldMappingTransformation(FIELDS),
                rule_conditions=scope(),
            ),
        ],
    )
