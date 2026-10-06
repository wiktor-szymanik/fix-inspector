"""Repeating-group projections over the lossless flat field list.

The returned rows annotate indexes; they never reorder or remove wire fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .dictionary import FixDictionary, GroupDefinition
from .fields import FixField
from .message import FixMessage


@dataclass(slots=True)
class GroupInstance:
    definition: GroupDefinition
    instance_number: int
    field_indexes: list[int] = field(default_factory=list)


@dataclass(slots=True)
class GroupView:
    definition: GroupDefinition
    declared_count: int | None
    count_field_index: int
    instances: list[GroupInstance] = field(default_factory=list)
    issue: str = ""


@dataclass(slots=True)
class ProjectedField:
    wire_index: int
    field: FixField
    group_path: str = ""
    instance_number: int | None = None


@dataclass(slots=True)
class GroupProjection:
    fields: list[ProjectedField]
    groups: list[GroupView]


def _project_definition(
    message: FixMessage,
    definition: GroupDefinition,
    rows: list[ProjectedField],
) -> list[GroupView]:
    if not definition.count_tag:
        return []
    views: list[GroupView] = []
    member_tags = set(definition.member_tags)
    for count_index, field in enumerate(message.fields):
        if field.tag != definition.count_tag:
            continue
        try:
            declared = int(field.value)
            if declared < 0:
                raise ValueError
        except ValueError:
            declared = None
        view = GroupView(definition, declared, count_index)
        views.append(view)
        index = count_index + 1
        current: GroupInstance | None = None
        while index < len(message.fields) and message.fields[index].tag in member_tags:
            member = message.fields[index]
            if current is None or (
                definition.delimiter_tag is not None
                and member.tag == definition.delimiter_tag
                and current.field_indexes
            ):
                current = GroupInstance(definition, len(view.instances) + 1)
                view.instances.append(current)
            current.field_indexes.append(index)
            path = " / ".join(definition.path)
            rows[index].group_path = (
                f"{path}[{current.instance_number}]" if path else f"Group[{current.instance_number}]"
            )
            rows[index].instance_number = current.instance_number
            index += 1
        if declared is None:
            view.issue = "Invalid NumInGroup value"
        elif declared != len(view.instances):
            view.issue = f"Declared {declared}, rendered {len(view.instances)}"
    return views


def project_groups(message: FixMessage, dictionary: FixDictionary | None) -> GroupProjection:
    rows = [ProjectedField(index, item) for index, item in enumerate(message.fields)]
    if dictionary is None:
        return GroupProjection(rows, [])
    groups: list[GroupView] = []
    for definition in dictionary.groups_for_message(message.msg_type):
        groups.extend(_project_definition(message, definition, rows))
    return GroupProjection(rows, groups)


__all__ = [
    "GroupInstance",
    "GroupProjection",
    "GroupView",
    "ProjectedField",
    "project_groups",
]
