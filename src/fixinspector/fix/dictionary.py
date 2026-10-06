"""QuickFIX/J XML dictionary reader used by protocol and presentation layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import xml.etree.ElementTree as ET


@dataclass(slots=True)
class FieldDefinition:
    tag: str
    name: str
    field_type: str
    enums: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class GroupDefinition:
    count_tag: str
    name: str
    path: list[str] = field(default_factory=list)
    required: bool = False
    delimiter_tag: str | None = None
    member_tags: list[str] = field(default_factory=list)
    direct_member_tags: list[str] = field(default_factory=list)
    required_member_tags: set[str] = field(default_factory=set)
    nested_groups: list["GroupDefinition"] = field(default_factory=list)


@dataclass(slots=True)
class MessageDefinition:
    msg_type: str
    name: str
    category: str
    required_tags: set[str] = field(default_factory=set)
    tag_paths: dict[str, list[str]] = field(default_factory=dict)
    groups: list[GroupDefinition] = field(default_factory=list)


class FixDictionary:
    FALLBACK_MESSAGES = {
        "A": ("Logon", "admin"),
        "0": ("Heartbeat", "admin"),
        "1": ("TestRequest", "admin"),
        "2": ("ResendRequest", "admin"),
        "3": ("Reject", "admin"),
        "4": ("SequenceReset", "admin"),
        "5": ("Logout", "admin"),
        "D": ("NewOrderSingle", "app"),
        "F": ("OrderCancelRequest", "app"),
        "G": ("OrderCancelReplaceRequest", "app"),
        "8": ("ExecutionReport", "app"),
        "9": ("OrderCancelReject", "app"),
        "B": ("News", "app"),
        "H": ("OrderStatusRequest", "app"),
        "AN": ("RequestForPositions", "app"),
        "AP": ("PositionReport", "app"),
        "J": ("BusinessMessageReject", "app"),
    }

    def __init__(self) -> None:
        self.fields_by_tag: dict[str, FieldDefinition] = {}
        self.tags_by_name: dict[str, str] = {}
        self.messages: dict[str, MessageDefinition] = {}
        self._component_xml: dict[str, ET.Element] = {}

    @classmethod
    def from_files(cls, *paths: str | Path) -> "FixDictionary":
        result = cls()
        for path in paths:
            if path:
                result.load_file(path)
        return result

    def load_file(self, path: str | Path) -> None:
        root = ET.parse(Path(path)).getroot()

        components = root.find("components")
        if components is not None:
            for node in components.findall("component"):
                name = node.attrib.get("name")
                if name:
                    self._component_xml[name] = node

        fields = root.find("fields")
        if fields is not None:
            for node in fields.findall("field"):
                tag = node.attrib.get("number", "")
                if not tag:
                    continue
                name = node.attrib.get("name", tag)
                field_type = node.attrib.get("type", "STRING").upper()
                enums = {
                    value.attrib.get("enum", ""): value.attrib.get("description", "")
                    for value in node.findall("value")
                    if value.attrib.get("enum") is not None
                }
                self.fields_by_tag[tag] = FieldDefinition(tag, name, field_type, enums)
                self.tags_by_name[name] = tag

        messages = root.find("messages")
        if messages is not None:
            for node in messages.findall("message"):
                msg_type = node.attrib.get("msgtype", "")
                if not msg_type:
                    continue
                definition = MessageDefinition(
                    msg_type=msg_type,
                    name=node.attrib.get("name", msg_type),
                    category=node.attrib.get("msgcat", "app"),
                )
                self._walk_schema(node, definition, [], True, True)
                self.messages[msg_type] = definition

    def _walk_schema(
        self,
        node: ET.Element,
        message: MessageDefinition,
        path: list[str],
        ancestors_required: bool,
        top_level: bool,
        seen_components: set[str] | None = None,
        active_group: GroupDefinition | None = None,
    ) -> None:
        seen = set() if seen_components is None else seen_components
        for child in list(node):
            kind = child.tag.lower()
            required_here = child.attrib.get("required", "N") == "Y"
            if kind == "field":
                tag = self.tags_by_name.get(child.attrib.get("name", ""))
                if not tag:
                    continue
                message.tag_paths.setdefault(tag, path.copy())
                if active_group is not None:
                    if tag not in active_group.member_tags:
                        active_group.member_tags.append(tag)
                    if tag not in active_group.direct_member_tags:
                        active_group.direct_member_tags.append(tag)
                    if required_here:
                        active_group.required_member_tags.add(tag)
                    if active_group.delimiter_tag is None:
                        active_group.delimiter_tag = tag
                if top_level and ancestors_required and required_here:
                    message.required_tags.add(tag)
            elif kind == "group":
                name = child.attrib.get("name", "")
                count_tag = self.tags_by_name.get(name)
                if count_tag:
                    message.tag_paths.setdefault(count_tag, path.copy())
                    if active_group is not None and count_tag not in active_group.member_tags:
                        active_group.member_tags.append(count_tag)
                    if active_group is not None and count_tag not in active_group.direct_member_tags:
                        active_group.direct_member_tags.append(count_tag)
                    if active_group is not None and required_here:
                        active_group.required_member_tags.add(count_tag)
                    if top_level and ancestors_required and required_here:
                        message.required_tags.add(count_tag)
                definition = GroupDefinition(
                    count_tag=count_tag or "",
                    name=name,
                    path=path + ([name] if name else []),
                    required=ancestors_required and required_here,
                )
                message.groups.append(definition)
                if active_group is not None:
                    active_group.nested_groups.append(definition)
                self._walk_schema(
                    child,
                    message,
                    path + ([name] if name else []),
                    ancestors_required and required_here,
                    False,
                    seen,
                    definition,
                )
                if active_group is not None:
                    for member_tag in definition.member_tags:
                        if member_tag not in active_group.member_tags:
                            active_group.member_tags.append(member_tag)
            elif kind == "component":
                name = child.attrib.get("name", "")
                if not name or name in seen:
                    continue
                component = self._component_xml.get(name)
                if component is None:
                    continue
                self._walk_schema(
                    component,
                    message,
                    path + [name],
                    ancestors_required and required_here,
                    top_level,
                    seen | {name},
                    active_group,
                )

    def field(self, tag: str) -> FieldDefinition | None:
        return self.fields_by_tag.get(str(tag))

    def message(self, msg_type: str) -> MessageDefinition | None:
        return self.messages.get(msg_type)

    def message_name(self, msg_type: str) -> str:
        definition = self.messages.get(msg_type)
        return definition.name if definition else self.FALLBACK_MESSAGES.get(msg_type, (msg_type, "app"))[0]

    def message_category(self, msg_type: str) -> str:
        definition = self.messages.get(msg_type)
        return definition.category if definition else self.FALLBACK_MESSAGES.get(msg_type, (msg_type, "app"))[1]

    def is_admin(self, msg_type: str) -> bool:
        return self.message_category(msg_type).lower() == "admin"

    def group_path(self, msg_type: str, tag: str) -> str:
        definition = self.messages.get(msg_type)
        if not definition:
            return ""
        return " / ".join(definition.tag_paths.get(str(tag), []))

    def groups_for_message(self, msg_type: str) -> list[GroupDefinition]:
        definition = self.messages.get(msg_type)
        return list(definition.groups) if definition else []

    def messages_using_tag(self, tag: str) -> list[MessageDefinition]:
        key = str(tag)
        return [message for message in self.messages.values() if key in message.tag_paths]

__all__ = ["FieldDefinition", "FixDictionary", "GroupDefinition", "MessageDefinition"]
