"""Dictionary-driven Composer form model with flat, lossless FIX output order."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..fix.dictionary import FieldDefinition, FixDictionary, GroupDefinition
from ..fix.fields import FixField
from ..fix.groups import project_groups
from ..fix.parser import decode_value, parse_message
from ..fix.serializer import serialize_structured


STRUCTURAL_TAGS = frozenset({"8", "9", "10", "35", "34", "49", "56", "52"})


@dataclass(slots=True)
class ComposerField:
    tag: str
    name: str
    field_type: str
    required: bool
    enum_options: dict[str, str] = field(default_factory=dict)
    path: tuple[str, ...] = ()
    value: str = ""
    enabled: bool = False
    hint: str = ""
    security_hint: str = ""

    @classmethod
    def from_definition(
        cls,
        definition: FieldDefinition | None,
        tag: str,
        *,
        required: bool,
        path: tuple[str, ...] = (),
    ) -> "ComposerField":
        return cls(
            str(tag),
            definition.name if definition else str(tag),
            definition.field_type if definition else "STRING",
            required,
            dict(definition.enums) if definition else {},
            path,
            "",
            required,
        )


@dataclass(slots=True)
class ComposerGroupInstance:
    fields: dict[str, ComposerField]
    groups: dict[str, "ComposerGroup"]


@dataclass(slots=True)
class ComposerGroup:
    definition: GroupDefinition
    dictionary: FixDictionary
    instances: list[ComposerGroupInstance] = field(default_factory=list)

    def add_instance(self) -> ComposerGroupInstance:
        nested_by_tag = {item.count_tag: item for item in self.definition.nested_groups}
        fields: dict[str, ComposerField] = {}
        groups: dict[str, ComposerGroup] = {}
        for tag in self.definition.direct_member_tags:
            nested = nested_by_tag.get(tag)
            if nested is not None:
                groups[tag] = ComposerGroup(nested, self.dictionary)
                continue
            fields[tag] = ComposerField.from_definition(
                self.dictionary.field(tag),
                tag,
                required=tag in self.definition.required_member_tags,
                path=tuple(self.definition.path),
            )
        instance = ComposerGroupInstance(fields, groups)
        self.instances.append(instance)
        return instance

    def remove_instance(self, index: int) -> None:
        if 0 <= index < len(self.instances):
            self.instances.pop(index)

    def to_fields(self) -> list[FixField]:
        if not self.instances and not self.definition.required:
            return []
        result = [FixField(self.definition.count_tag, str(len(self.instances)).encode("ascii"))]
        for instance in self.instances:
            for tag in self.definition.direct_member_tags:
                nested = instance.groups.get(tag)
                if nested is not None:
                    result.extend(nested.to_fields())
                    continue
                item = instance.fields.get(tag)
                if item is not None and (item.required or item.enabled):
                    result.append(FixField(tag, item.value.encode("utf-8")))
        return result

    def validation_issues(self) -> list[str]:
        issues: list[str] = []
        if self.definition.required and not self.instances:
            issues.append(f"Required group {self.definition.name} ({self.definition.count_tag}) has no instances")
        for index, instance in enumerate(self.instances, start=1):
            for item in instance.fields.values():
                issues.extend(_field_issues(item, f"{self.definition.name}[{index}]") )
            for nested in instance.groups.values():
                issues.extend(nested.validation_issues())
        return issues


@dataclass(slots=True)
class ComposerForm:
    dictionary: FixDictionary
    msg_type: str
    message_name: str
    required_fields: list[ComposerField]
    optional_fields: list[ComposerField]
    groups: list[ComposerGroup]
    message_hint: str = ""

    @classmethod
    def from_dictionary(cls, dictionary: FixDictionary, msg_type: str, overlay=None) -> "ComposerForm":
        definition = dictionary.message(msg_type)
        if definition is None:
            raise KeyError(f"MsgType {msg_type!r} is not present in the loaded dictionary")
        if dictionary.is_admin(msg_type):
            raise ValueError("Composer creates application messages only; session/admin traffic is excluded")

        root_groups = [
            group
            for group in definition.groups
            if not any(group is nested for parent in definition.groups for nested in parent.nested_groups)
        ]
        grouped_tags = {
            tag
            for group in root_groups
            for tag in ({group.count_tag} | set(group.member_tags))
        }
        required: list[ComposerField] = []
        optional: list[ComposerField] = []
        for tag, path in definition.tag_paths.items():
            if tag in STRUCTURAL_TAGS or tag in grouped_tags:
                continue
            item = ComposerField.from_definition(
                dictionary.field(tag),
                tag,
                required=tag in definition.required_tags,
                path=tuple(path),
            )
            if overlay is not None:
                item.hint = overlay.field_hint(msg_type, tag)
                item.security_hint = overlay.security_hint(msg_type, tag)
            (required if item.required else optional).append(item)
        groups = [ComposerGroup(group, dictionary) for group in root_groups]
        return cls(
            dictionary,
            msg_type,
            definition.name,
            required,
            optional,
            groups,
            overlay.message_hint(msg_type) if overlay is not None else "",
        )

    def field(self, tag: str) -> ComposerField | None:
        key = str(tag)
        return next((item for item in self.required_fields + self.optional_fields if item.tag == key), None)

    def apply_raw(self, raw: bytes) -> None:
        """Hydrate known form fields/groups while leaving unknown/duplicate bytes to the shared editor."""
        message = parse_message(raw, self.dictionary)
        if message.msg_type != self.msg_type:
            raise ValueError(f"Template MsgType {message.msg_type} does not match Composer form {self.msg_type}")
        for item in self.required_fields + self.optional_fields:
            value = message.first(item.tag)
            if value is not None:
                item.value = decode_value(value, message.encoding)
                item.enabled = True
        projection = project_groups(message, self.dictionary)
        for group in self.groups:
            group.instances.clear()
            view = next(
                (
                    current
                    for current in projection.groups
                    if current.definition.count_tag == group.definition.count_tag
                ),
                None,
            )
            if view is None:
                continue
            for projected_instance in view.instances:
                instance = group.add_instance()
                for index in projected_instance.field_indexes:
                    wire_field = message.fields[index]
                    item = instance.fields.get(wire_field.tag)
                    if item is not None:
                        item.value = decode_value(wire_field.value, message.encoding)
                        item.enabled = True

    def to_fields(self) -> list[FixField]:
        definition = self.dictionary.message(self.msg_type)
        if definition is None:
            raise KeyError(self.msg_type)
        top = {item.tag: item for item in self.required_fields + self.optional_fields}
        groups = {item.definition.count_tag: item for item in self.groups}
        group_member_tags = {tag for group in self.groups for tag in group.definition.member_tags}
        result = [
            FixField("8", b"FIXT.1.1"),
            FixField("9", b"0"),
            FixField("35", self.msg_type.encode("ascii")),
            FixField("34", b"1"),
            FixField("49", b"COMPOSER"),
            FixField("56", b"ACTIVE_SESSION"),
            FixField("52", datetime.now(timezone.utc).strftime("%Y%m%d-%H:%M:%S.%f")[:-3].encode("ascii")),
        ]
        for tag in definition.tag_paths:
            group = groups.get(tag)
            if group is not None:
                result.extend(group.to_fields())
                continue
            if tag in group_member_tags:
                continue
            item = top.get(tag)
            if item is not None and (item.required or item.enabled):
                result.append(FixField(tag, item.value.encode("utf-8")))
        result.append(FixField("10", b"000"))
        return result

    def to_raw(self) -> bytes:
        return serialize_structured(self.to_fields())

    def validation_issues(self) -> list[str]:
        issues: list[str] = []
        for item in self.required_fields + self.optional_fields:
            issues.extend(_field_issues(item))
        for group in self.groups:
            issues.extend(group.validation_issues())
        return issues


def _field_issues(item: ComposerField, prefix: str = "") -> list[str]:
    label = f"{prefix} {item.name} ({item.tag})".strip()
    if item.required and not item.value:
        return [f"Required field {label} is empty"]
    if not (item.required or item.enabled) or not item.value:
        return []
    issues: list[str] = []
    numeric_types = {"INT", "LENGTH", "NUMINGROUP", "SEQNUM", "TAGNUM", "DAYOFMONTH"}
    decimal_types = {"FLOAT", "QTY", "PRICE", "PRICEOFFSET", "AMT", "PERCENTAGE"}
    if item.field_type in numeric_types:
        try:
            int(item.value)
        except ValueError:
            issues.append(f"{label} expects {item.field_type}; arbitrary invalid value will still be retained")
    elif item.field_type in decimal_types:
        try:
            float(item.value)
        except ValueError:
            issues.append(f"{label} expects {item.field_type}; arbitrary invalid value will still be retained")
    if item.enum_options and item.value not in item.enum_options:
        issues.append(f"{label} is outside the dictionary enum set (allowed for security testing)")
    return issues


__all__ = [
    "ComposerField",
    "ComposerForm",
    "ComposerGroup",
    "ComposerGroupInstance",
]
