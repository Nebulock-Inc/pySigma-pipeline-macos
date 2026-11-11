"""macOS ESF pipeline for ECS backends."""

from dataclasses import dataclass

from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaTransformationError
from sigma.processing.conditions import (
    IncludeFieldCondition,
    RuleProcessingCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    ConvertTypeTransformation,
    DetectionItemFailureTransformation,
    FieldMappingTransformation,
    RuleFailureTransformation,
    Transformation,
)
from sigma.rule import SigmaRule

from .taxonomy import ESF_CATEGORIES, ESF_FIELDS


@dataclass
class MacOSESFCondition(RuleProcessingCondition):
    """Match macOS ESF rules: product macos, no service or service endpointsecurity.

    LogsourceCondition can't express "service is None"; a service-less one matches
    every service, including unifiedlog rules in categories shared with ESF.
    category None matches any category.
    """

    category: str | None = None

    def match(self, rule) -> bool:
        if isinstance(rule, SigmaCorrelationRule):
            # As LogsourceCondition: a correlation matches when a resolved referenced rule does.
            return any(hasattr(ref, "rule") and self.match(ref.rule) for ref in rule.referenced_rules)
        ls = rule.logsource
        return (
            ls.product == "macos"
            and ls.service in (None, "endpointsecurity")
            and (self.category is None or ls.category == self.category)
        )


def require_lowercase_logsource(rule: SigmaRule, kind: str) -> None:
    """Fail a rule whose logsource product, service or category isn't lowercase.

    The macOS conditions match exact lowercase values, so a wrong-case value would
    convert without the field mapping and category condition.
    """
    for name in ("product", "service", "category"):
        value = getattr(rule.logsource, name)
        if value and value != value.lower():
            raise SigmaTransformationError(
                f"logsource {name} '{value}' must be lowercase ('{value.lower()}') for {kind} rules", source=rule.source
            )


class MacOSESFCategoryCheckTransformation(Transformation):
    """
    Check that macOS ESF rules have a valid category.

    Only applies to product=macos rules that are NOT service=unifiedlog.
    Fails if category is missing or not in ESF_CATEGORIES.
    """

    def __init__(self, known_categories: list[str]):
        super().__init__()
        # Store lowercase categories for case-insensitive comparison
        self.known_categories = {cat.lower() for cat in known_categories}

    def apply(self, rule: SigmaRule) -> None:
        """Check rule category and fail if unknown or missing.

        Matches product, service and category case-insensitively so that a
        wrong-case macOS ESF rule (e.g. MacOS, Process_Creation) fails here
        instead of silently skipping the exact-match MacOSESFCondition items.
        Correlation rules have no logsource; their referenced rules are checked themselves.
        """
        if not isinstance(rule, SigmaRule):
            return
        # Get logsource values, treating None as missing, and normalize to lowercase for comparison
        product = rule.logsource.product.lower() if rule.logsource.product else None
        service = rule.logsource.service.lower() if rule.logsource.service else None
        category = rule.logsource.category.lower() if rule.logsource.category else None

        # Only check macOS rules (case-insensitive)
        if product != "macos":
            return

        # Skip unified log rules (case-insensitive)
        if service == "unifiedlog":
            return

        # If service is specified and it's not endpointsecurity, skip
        # (this pipeline only handles ESF rules: no service or service=endpointsecurity)
        if service is not None and service != "endpointsecurity":
            return

        # Check category
        if category is None:
            raise SigmaTransformationError("category missing; required for macOS ESF rules", source=rule.source)

        # Category lookup is case-insensitive (lowercase both sides)
        if category not in self.known_categories:
            # Use original case from rule for error message
            raise SigmaTransformationError(
                f"category '{rule.logsource.category}' not supported on macOS ESF", source=rule.source
            )

        require_lowercase_logsource(rule, "macOS ESF")


def macos_esf_ecs() -> ProcessingPipeline:
    """
    Pipeline for macOS ESF rules targeting ECS-compliant backends.

    Converts product: macos rules (with no service or service: endpointsecurity)
    into queries over Defend-shaped ECS documents.
    """
    items = []

    # Fail rules with unknown or missing categories
    # This catches any ESF-scoped rule whose category is not in ESF_CATEGORIES
    known_categories = list(ESF_CATEGORIES.keys())

    # Fail rules with known unsupported categories first
    unsupported_categories = ["network_connection", "dns_query"]
    for unsupported in unsupported_categories:
        items.append(
            ProcessingItem(
                identifier=f"macos_esf_ecs_fail_{unsupported}",
                transformation=RuleFailureTransformation(f"category '{unsupported}' not supported on macOS ESF"),
                rule_conditions=[MacOSESFCondition(category=unsupported)],
            )
        )

    # Fail ESF rules with unknown/missing categories (not in ESF_CATEGORIES)
    # Custom transformation that checks:
    # - product=macos AND
    # - service missing or endpointsecurity AND
    # - (category missing OR category not in ESF_CATEGORIES)
    # Does NOT fail non-macOS or non-ESF-service rules (they pass through untouched)
    # Because it fails first, the category-less MacOSESFCondition() items below only see known categories.
    items.append(
        ProcessingItem(
            identifier="macos_esf_ecs_fail_unknown_category",
            transformation=MacOSESFCategoryCheckTransformation(known_categories),
        )
    )

    # Fail on unmapped Sigma fields (fields not in ESF_FIELDS with ecs values)
    # This must come BEFORE field mapping and AddCondition items
    # Only applies to ESF rules (no service or service: endpointsecurity)
    mapped_sigma_fields = [field for field in ESF_FIELDS.keys()]

    items.append(
        ProcessingItem(
            identifier="macos_esf_ecs_unmapped_field_failure",
            transformation=DetectionItemFailureTransformation("Field not supported in macOS ESF ECS mapping"),
            rule_conditions=[MacOSESFCondition()],
            field_name_conditions=[IncludeFieldCondition(mapped_sigma_fields)],
            field_name_condition_negation=True,  # Fail if field is NOT in the list
        )
    )

    # Build per-category conditions from taxonomy
    for category, cat_data in ESF_CATEGORIES.items():
        # Build the condition dict from the ecs dict
        conditions = {}
        for field, value in cat_data.ecs.items():
            # If value is a tuple (multiple values), convert to list for OR
            if isinstance(value, tuple):
                conditions[field] = list(value)
            else:
                conditions[field] = value

        items.append(
            ProcessingItem(
                identifier=f"macos_esf_ecs_category_{category}",
                transformation=AddConditionTransformation(conditions),
                rule_conditions=[MacOSESFCondition(category=category)],
            )
        )

    # Build field mapping from taxonomy
    # Scoped to ESF rules only (no service or service: endpointsecurity)
    field_mappings = {}
    for sigma_field, field_data in ESF_FIELDS.items():
        ecs_field = field_data.ecs
        # If ecs field is a list, use the first one (could also use all, but typically we want the primary)
        if isinstance(ecs_field, list):
            field_mappings[sigma_field] = ecs_field[0]
        else:
            field_mappings[sigma_field] = ecs_field

    items.append(
        ProcessingItem(
            identifier="macos_esf_ecs_field_mapping",
            transformation=FieldMappingTransformation(field_mappings),
            rule_conditions=[MacOSESFCondition()],
        )
    )

    # Convert specific fields to string type
    # Scoped to ESF rules only (no service or service: endpointsecurity)
    string_fields = ["user.id", "user.target.id", "user.target.group.id", "process.pid", "process.parent.pid"]
    items.append(
        ProcessingItem(
            identifier="macos_esf_ecs_string_conversion",
            transformation=ConvertTypeTransformation("str"),
            field_name_conditions=[IncludeFieldCondition(string_fields)],
            rule_conditions=[MacOSESFCondition()],
        )
    )

    return ProcessingPipeline(name="macos_esf_ecs", priority=20, items=items)
