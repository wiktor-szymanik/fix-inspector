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
class MessageDefinition:
    msg_type: str
    name: str
    category: str
    required_tags: set[str] = field(default_factory=set)
    tag_paths: dict[str, list[str]] = field(default_factory=dict)


class FixDictionary:
    """Small reader for QuickFIX/J XML data dictionaries.

    It intentionally focuses on what an intercepting proxy needs:
    field names/types/enums, message names/categories, top-level required
    fields and a best-effort group/component path for display.
    """

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
        path = Path(path)
        tree = ET.parse(path)
        root = tree.getroot()

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
                name = node.attrib.get("name", tag)
                field_type = node.attrib.get("type", "STRING").upper()
                enums = {
                    v.attrib.get("enum", ""): v.attrib.get("description", "")
                    for v in node.findall("value")
                    if v.attrib.get("enum") is not None
                }
                if tag:
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
                self._walk_schema(node, definition, path=[], ancestors_required=True, top_level=True)
                self.messages[msg_type] = definition

    def _walk_schema(
        self,
        node: ET.Element,
        message: MessageDefinition,
        path: list[str],
        ancestors_required: bool,
        top_level: bool,
        seen_components: set[str] | None = None,
    ) -> None:
        seen_components = set() if seen_components is None else seen_components

        for child in list(node):
            tag_name = child.tag.lower()
            required_here = child.attrib.get("required", "N") == "Y"

            if tag_name == "field":
                field_name = child.attrib.get("name", "")
                tag = self.tags_by_name.get(field_name)
                if not tag:
                    continue
                if path:
                    message.tag_paths.setdefault(tag, path.copy())
                if top_level and ancestors_required and required_here:
                    message.required_tags.add(tag)

            elif tag_name == "group":
                group_name = child.attrib.get("name", "")
                count_tag = self.tags_by_name.get(group_name)
                if count_tag:
                    message.tag_paths.setdefault(count_tag, path.copy())
                    if top_level and ancestors_required and required_here:
                        message.required_tags.add(count_tag)
                self._walk_schema(
                    child,
                    message,
                    path=path + ([group_name] if group_name else []),
                    ancestors_required=ancestors_required and required_here,
                    top_level=False,
                    seen_components=seen_components,
                )

            elif tag_name == "component":
                component_name = child.attrib.get("name", "")
                if not component_name or component_name in seen_components:
                    continue
                component = self._component_xml.get(component_name)
                if component is None:
                    continue
                next_seen = seen_components | {component_name}
                self._walk_schema(
                    component,
                    message,
                    path=path + [component_name],
                    ancestors_required=ancestors_required and required_here,
                    top_level=top_level,
                    seen_components=next_seen,
                )

    def field(self, tag: str) -> FieldDefinition | None:
        return self.fields_by_tag.get(str(tag))

    def message(self, msg_type: str) -> MessageDefinition | None:
        return self.messages.get(msg_type)

    def message_name(self, msg_type: str) -> str:
        definition = self.messages.get(msg_type)
        if definition:
            return definition.name
        return self.FALLBACK_MESSAGES.get(msg_type, (msg_type, "app"))[0]

    def message_category(self, msg_type: str) -> str:
        definition = self.messages.get(msg_type)
        if definition:
            return definition.category
        return self.FALLBACK_MESSAGES.get(msg_type, (msg_type, "app"))[1]

    def is_admin(self, msg_type: str) -> bool:
        return self.message_category(msg_type).lower() == "admin"

    def group_path(self, msg_type: str, tag: str) -> str:
        definition = self.messages.get(msg_type)
        if not definition:
            return ""
        path = definition.tag_paths.get(str(tag), [])
        return " / ".join(path)
