from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
import itertools
import random
import re
import threading
from typing import Iterable, Mapping


DIRECTIONS = ("C→S", "S→C")
MAX_ONE_SHOT_MESSAGES = 1_000
MAX_DUPLICATE_COPIES = 10
MAX_DELAY_MS = 60_000


class FaultAction(str, Enum):
    NORMAL = "NORMAL"
    DROP = "DROP"
    PAUSE = "PAUSE"
    DELAY = "DELAY"
    DUPLICATE = "DUPLICATE"


class MessageCategory(str, Enum):
    ANY = "ANY"
    APPLICATION = "APPLICATION"
    ADMIN = "ADMIN"


class DisconnectSide(str, Enum):
    CLIENT = "CLIENT"
    SERVER = "SERVER"
    BOTH = "BOTH"


class DisconnectEvent(str, Enum):
    RECEIVED = "RECEIVED"
    FORWARDED = "FORWARDED"
    DROPPED = "DROPPED"


@dataclass(frozen=True, slots=True)
class TagCondition:
    tag: str
    value: str

    def __post_init__(self) -> None:
        if not str(self.tag).isdigit() or int(self.tag) <= 0:
            raise ValueError(f"Rule tag must be a positive integer: {self.tag!r}")


@dataclass(frozen=True, slots=True)
class FaultRule:
    rule_id: int
    name: str
    direction: str = "ANY"
    msg_type: str = ""
    category: MessageCategory = MessageCategory.ANY
    conditions: tuple[TagCondition, ...] = ()
    action: FaultAction = FaultAction.NORMAL
    delay_ms: int = 0
    jitter_ms: int = 0
    duplicate_copies: int = 1
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.direction not in {*DIRECTIONS, "ANY"}:
            raise ValueError(f"Unknown rule direction: {self.direction}")
        if not 0 <= int(self.delay_ms) <= MAX_DELAY_MS:
            raise ValueError(f"Delay must be between 0 and {MAX_DELAY_MS} ms")
        if not 0 <= int(self.jitter_ms) <= MAX_DELAY_MS:
            raise ValueError(f"Jitter must be between 0 and {MAX_DELAY_MS} ms")
        if not 1 <= int(self.duplicate_copies) <= MAX_DUPLICATE_COPIES:
            raise ValueError(
                f"Duplicate copies must be between 1 and {MAX_DUPLICATE_COPIES}"
            )


@dataclass(frozen=True, slots=True)
class FaultDecision:
    action: FaultAction = FaultAction.NORMAL
    delay_ms: int = 0
    duplicate_copies: int = 0
    matched_rule: str = ""
    reason: str = "Direction default NORMAL"


@dataclass(frozen=True, slots=True)
class OneShotAction:
    action: FaultAction
    remaining: int
    delay_ms: int = 0
    jitter_ms: int = 0
    duplicate_copies: int = 1


@dataclass(frozen=True, slots=True)
class DisconnectTrigger:
    trigger_id: int
    side: DisconnectSide
    direction: str
    event: DisconnectEvent
    remaining: int = 1


@dataclass(frozen=True, slots=True)
class FaultEvent:
    event_id: int
    timestamp: datetime
    direction: str
    kind: str
    summary: str
    record_id: int | None = None
    msg_type: str = ""


@dataclass(slots=True)
class DirectionBehaviour:
    global_mode: FaultAction = FaultAction.NORMAL
    application_mode: FaultAction = FaultAction.NORMAL
    admin_mode: FaultAction = FaultAction.NORMAL
    delay_enabled: bool = False
    delay_ms: int = 0
    jitter_ms: int = 0
    delay_category: MessageCategory = MessageCategory.APPLICATION


@dataclass(frozen=True, slots=True)
class ProxyBehaviourSnapshot:
    client_to_server: DirectionBehaviour
    server_to_client: DirectionBehaviour
    one_shots: Mapping[str, OneShotAction]
    rules: tuple[FaultRule, ...]
    disconnect_triggers: tuple[DisconnectTrigger, ...]
    events: tuple[FaultEvent, ...]

    @property
    def active_rule_count(self) -> int:
        return sum(rule.enabled for rule in self.rules)


class ProxyBehaviourController:
    """Own all fault-policy state and evaluate messages atomically.

    Precedence is intentionally fixed and exposed by ``PRECEDENCE``:
    emergency direction mode, one-shot, first enabled rule, category default,
    direction delay, then NORMAL.  A matching NORMAL rule is an explicit
    bypass of lower-precedence category and delay defaults.
    """

    PRECEDENCE = (
        "Global direction DROP/PAUSE",
        "One-shot action",
        "First matching enabled rule",
        "Application/admin direction default",
        "Direction delay",
        "NORMAL",
    )

    def __init__(self, dictionary, *, random_seed: int = 0, max_events: int = 1_000) -> None:
        self._dictionary = dictionary
        self._directions = {direction: DirectionBehaviour() for direction in DIRECTIONS}
        self._one_shots: dict[str, OneShotAction] = {}
        self._rules: list[FaultRule] = []
        self._disconnect_triggers: list[DisconnectTrigger] = []
        self._events: list[FaultEvent] = []
        self._rule_ids = itertools.count(1)
        self._trigger_ids = itertools.count(1)
        self._event_ids = itertools.count(1)
        self._random = random.Random(random_seed)
        self._max_events = max(10, int(max_events))
        self._secret_tags = {"553"}
        self._lock = threading.RLock()

    def set_dictionary(self, dictionary) -> None:
        with self._lock:
            self._dictionary = dictionary

    def set_secret_tags(self, tags: Iterable[str]) -> None:
        with self._lock:
            self._secret_tags = {str(tag) for tag in tags} | {"553"}

    def direction(self, direction: str) -> DirectionBehaviour:
        self._validate_direction(direction)
        with self._lock:
            return replace(self._directions[direction])

    def set_global_mode(self, direction: str, mode: FaultAction | str) -> None:
        self._validate_direction(direction)
        action = self._coerce_action(mode)
        if action not in {FaultAction.NORMAL, FaultAction.DROP, FaultAction.PAUSE}:
            raise ValueError("Global direction mode must be NORMAL, DROP or PAUSE")
        with self._lock:
            self._directions[direction].global_mode = action

    def set_category_mode(
        self,
        direction: str,
        category: MessageCategory | str,
        mode: FaultAction | str,
    ) -> None:
        self._validate_direction(direction)
        selected_category = self._coerce_category(category)
        action = self._coerce_action(mode)
        if selected_category not in {MessageCategory.APPLICATION, MessageCategory.ADMIN}:
            raise ValueError("Category mode requires APPLICATION or ADMIN")
        if action not in {FaultAction.NORMAL, FaultAction.DROP, FaultAction.PAUSE}:
            raise ValueError("Category mode must be NORMAL, DROP or PAUSE")
        with self._lock:
            state = self._directions[direction]
            if selected_category is MessageCategory.APPLICATION:
                state.application_mode = action
            else:
                state.admin_mode = action

    def set_delay(
        self,
        direction: str,
        *,
        enabled: bool,
        delay_ms: int,
        jitter_ms: int = 0,
        category: MessageCategory | str = MessageCategory.APPLICATION,
    ) -> None:
        self._validate_direction(direction)
        delay = self._bounded_delay(delay_ms, "Delay")
        jitter = self._bounded_delay(jitter_ms, "Jitter")
        selected_category = self._coerce_category(category)
        with self._lock:
            state = self._directions[direction]
            state.delay_enabled = bool(enabled)
            state.delay_ms = delay
            state.jitter_ms = jitter
            state.delay_category = selected_category

    def arm_one_shot(
        self,
        direction: str,
        action: FaultAction | str,
        count: int = 1,
        *,
        delay_ms: int = 0,
        jitter_ms: int = 0,
        duplicate_copies: int = 1,
    ) -> None:
        self._validate_direction(direction)
        selected = self._coerce_action(action)
        if selected not in {
            FaultAction.DROP,
            FaultAction.PAUSE,
            FaultAction.DELAY,
            FaultAction.DUPLICATE,
        }:
            raise ValueError("One-shot action must be DROP, PAUSE, DELAY or DUPLICATE")
        remaining = int(count)
        if not 1 <= remaining <= MAX_ONE_SHOT_MESSAGES:
            raise ValueError(
                f"One-shot count must be between 1 and {MAX_ONE_SHOT_MESSAGES}"
            )
        copies = int(duplicate_copies)
        if not 1 <= copies <= MAX_DUPLICATE_COPIES:
            raise ValueError(
                f"Duplicate copies must be between 1 and {MAX_DUPLICATE_COPIES}"
            )
        shot = OneShotAction(
            selected,
            remaining,
            self._bounded_delay(delay_ms, "Delay"),
            self._bounded_delay(jitter_ms, "Jitter"),
            copies,
        )
        with self._lock:
            self._one_shots[direction] = shot

    def clear_one_shot(self, direction: str) -> None:
        self._validate_direction(direction)
        with self._lock:
            self._one_shots.pop(direction, None)

    def add_rule(
        self,
        *,
        name: str,
        direction: str = "ANY",
        msg_type: str = "",
        category: MessageCategory | str = MessageCategory.ANY,
        conditions: Iterable[TagCondition | tuple[str, str]] = (),
        action: FaultAction | str = FaultAction.NORMAL,
        delay_ms: int = 0,
        jitter_ms: int = 0,
        duplicate_copies: int = 1,
        enabled: bool = True,
    ) -> FaultRule:
        normalized_conditions = tuple(
            item if isinstance(item, TagCondition) else TagCondition(str(item[0]), str(item[1]))
            for item in conditions
        )
        with self._lock:
            rule = FaultRule(
                next(self._rule_ids),
                str(name).strip() or "Unnamed rule",
                direction,
                str(msg_type).strip(),
                self._coerce_category(category),
                normalized_conditions,
                self._coerce_action(action),
                self._bounded_delay(delay_ms, "Delay"),
                self._bounded_delay(jitter_ms, "Jitter"),
                int(duplicate_copies),
                bool(enabled),
            )
            self._rules.append(rule)
            return rule

    def update_rule(self, rule_id: int, **changes) -> FaultRule:
        with self._lock:
            index = self._rule_index(rule_id)
            current = self._rules[index]
            if "conditions" in changes:
                changes["conditions"] = tuple(
                    item if isinstance(item, TagCondition) else TagCondition(str(item[0]), str(item[1]))
                    for item in changes["conditions"]
                )
            if "action" in changes:
                changes["action"] = self._coerce_action(changes["action"])
            if "category" in changes:
                changes["category"] = self._coerce_category(changes["category"])
            updated = replace(current, **changes)
            self._rules[index] = updated
            return updated

    def delete_rule(self, rule_id: int) -> None:
        with self._lock:
            self._rules.pop(self._rule_index(rule_id))

    def move_rule(self, rule_id: int, offset: int) -> None:
        with self._lock:
            index = self._rule_index(rule_id)
            target = max(0, min(len(self._rules) - 1, index + int(offset)))
            if target != index:
                self._rules.insert(target, self._rules.pop(index))

    def set_rule_enabled(self, rule_id: int, enabled: bool) -> None:
        self.update_rule(rule_id, enabled=bool(enabled))

    def rules(self) -> tuple[FaultRule, ...]:
        with self._lock:
            return tuple(self._rules)

    def arm_disconnect(
        self,
        side: DisconnectSide | str,
        direction: str,
        event: DisconnectEvent | str,
        count: int = 1,
    ) -> DisconnectTrigger:
        self._validate_direction(direction)
        remaining = int(count)
        if not 1 <= remaining <= MAX_ONE_SHOT_MESSAGES:
            raise ValueError(
                f"Disconnect trigger count must be between 1 and {MAX_ONE_SHOT_MESSAGES}"
            )
        trigger = DisconnectTrigger(
            next(self._trigger_ids),
            side if isinstance(side, DisconnectSide) else DisconnectSide(str(side).upper()),
            direction,
            event if isinstance(event, DisconnectEvent) else DisconnectEvent(str(event).upper()),
            remaining,
        )
        with self._lock:
            self._disconnect_triggers.append(trigger)
        return trigger

    def consume_disconnects(
        self,
        direction: str,
        event: DisconnectEvent | str,
    ) -> tuple[DisconnectSide, ...]:
        self._validate_direction(direction)
        selected_event = (
            event if isinstance(event, DisconnectEvent) else DisconnectEvent(str(event).upper())
        )
        fired: list[DisconnectSide] = []
        with self._lock:
            retained: list[DisconnectTrigger] = []
            for trigger in self._disconnect_triggers:
                if trigger.direction != direction or trigger.event is not selected_event:
                    retained.append(trigger)
                    continue
                remaining = trigger.remaining - 1
                if remaining == 0:
                    fired.append(trigger.side)
                else:
                    retained.append(replace(trigger, remaining=remaining))
            self._disconnect_triggers = retained
        return tuple(fired)

    def evaluate(self, direction: str, message) -> FaultDecision:
        self._validate_direction(direction)
        category = (
            MessageCategory.ADMIN
            if self._dictionary.is_admin(message.msg_type)
            else MessageCategory.APPLICATION
        )
        with self._lock:
            state = self._directions[direction]
            if state.global_mode in {FaultAction.DROP, FaultAction.PAUSE}:
                return FaultDecision(
                    state.global_mode,
                    reason=f"{direction} global {state.global_mode.value}",
                )

            shot = self._one_shots.get(direction)
            if shot is not None:
                if shot.remaining <= 1:
                    self._one_shots.pop(direction, None)
                else:
                    self._one_shots[direction] = replace(shot, remaining=shot.remaining - 1)
                return self._decision_for_action(
                    shot.action,
                    shot.delay_ms,
                    shot.jitter_ms,
                    shot.duplicate_copies,
                    reason=f"{direction} one-shot {shot.action.value}",
                )

            for rule in self._rules:
                if rule.enabled and self._matches(rule, direction, category, message):
                    return self._decision_for_action(
                        rule.action,
                        rule.delay_ms,
                        rule.jitter_ms,
                        rule.duplicate_copies,
                        matched_rule=rule.name,
                        reason=f'First matching rule "{rule.name}"',
                    )

            category_mode = (
                state.admin_mode
                if category is MessageCategory.ADMIN
                else state.application_mode
            )
            if category_mode is not FaultAction.NORMAL:
                return FaultDecision(
                    category_mode,
                    reason=f"{direction} {category.value.lower()} default {category_mode.value}",
                )

            if state.delay_enabled and state.delay_category in {MessageCategory.ANY, category}:
                return self._decision_for_action(
                    FaultAction.DELAY,
                    state.delay_ms,
                    state.jitter_ms,
                    1,
                    reason=f"{direction} {category.value.lower()} direction delay",
                )
            return FaultDecision()

    def record_event(
        self,
        *,
        direction: str = "",
        kind: str,
        summary: str,
        record_id: int | None = None,
        msg_type: str = "",
    ) -> FaultEvent:
        """Append sanitized operational metadata; callers must never pass raw FIX."""
        safe_summary = str(summary)
        with self._lock:
            for tag in self._secret_tags:
                safe_summary = re.sub(
                    rf"(?<!\d)({re.escape(tag)}\s*=\s*)[^\x01␁|,;\r\n]*",
                    rf"\1<REDACTED>",
                    safe_summary,
                    flags=re.IGNORECASE,
                )
        event = FaultEvent(
            next(self._event_ids),
            datetime.now(timezone.utc),
            direction,
            str(kind),
            safe_summary,
            record_id,
            str(msg_type),
        )
        with self._lock:
            self._events.append(event)
            if len(self._events) > self._max_events:
                del self._events[: len(self._events) - self._max_events]
        return event

    def reset(self) -> None:
        with self._lock:
            self._directions = {direction: DirectionBehaviour() for direction in DIRECTIONS}
            self._one_shots.clear()
            self._disconnect_triggers.clear()
            self._rules = [replace(rule, enabled=False) for rule in self._rules]
        self.record_event(kind="RESET", summary="Proxy behaviour reset to safe NORMAL")

    def apply_preset(self, name: str) -> None:
        selected = name.strip().casefold()
        self.reset()
        if selected == "ambiguous application delivery":
            self.set_category_mode("S→C", MessageCategory.APPLICATION, FaultAction.DROP)
        elif selected == "server response delay":
            self.set_delay(
                "S→C",
                enabled=True,
                delay_ms=5_000,
                category=MessageCategory.APPLICATION,
            )
        elif selected == "client request blackhole":
            self.set_category_mode("C→S", MessageCategory.APPLICATION, FaultAction.DROP)
        elif selected != "clean":
            raise ValueError(f"Unknown Proxy Behaviour preset: {name}")
        self.record_event(kind="PRESET", summary=f'Configured preset "{name}"')

    def snapshot(self) -> ProxyBehaviourSnapshot:
        with self._lock:
            return ProxyBehaviourSnapshot(
                replace(self._directions["C→S"]),
                replace(self._directions["S→C"]),
                dict(self._one_shots),
                tuple(self._rules),
                tuple(self._disconnect_triggers),
                tuple(self._events),
            )

    def to_state(self, secret_tags: Iterable[str] = ("553",)) -> dict[str, object]:
        """Persist rules safely, always disabled; never persist active faults."""
        secrets = {str(tag) for tag in secret_tags} | {"553"}
        with self._lock:
            rules = []
            for rule in self._rules:
                payload = asdict(rule)
                payload["category"] = rule.category.value
                payload["action"] = rule.action.value
                payload["enabled"] = False
                payload["conditions"] = [
                    {
                        "tag": condition.tag,
                        "value": "<REDACTED>" if condition.tag in secrets else condition.value,
                    }
                    for condition in rule.conditions
                ]
                rules.append(payload)
            return {"rules": rules, "restore_policy": "disabled-safe-normal"}

    def restore_state(self, state: object) -> None:
        """Restore only disabled rule definitions into a clean NORMAL policy."""
        self.reset()
        if not isinstance(state, Mapping):
            return
        restored: list[FaultRule] = []
        highest_id = 0
        for payload in state.get("rules", []):
            if not isinstance(payload, Mapping):
                continue
            try:
                rule = FaultRule(
                    int(payload.get("rule_id", highest_id + 1)),
                    str(payload.get("name", "Restored rule")),
                    str(payload.get("direction", "ANY")),
                    str(payload.get("msg_type", "")),
                    self._coerce_category(payload.get("category", "ANY")),
                    tuple(
                        TagCondition(str(item.get("tag", "")), str(item.get("value", "")))
                        for item in payload.get("conditions", [])
                        if isinstance(item, Mapping)
                    ),
                    self._coerce_action(payload.get("action", "NORMAL")),
                    int(payload.get("delay_ms", 0)),
                    int(payload.get("jitter_ms", 0)),
                    int(payload.get("duplicate_copies", 1)),
                    False,
                )
            except (TypeError, ValueError):
                continue
            restored.append(rule)
            highest_id = max(highest_id, rule.rule_id)
        with self._lock:
            self._rules = restored
            self._rule_ids = itertools.count(highest_id + 1)

    def status_text(self, paused_count: int = 0) -> str:
        with self._lock:
            parts = []
            for direction in DIRECTIONS:
                state = self._directions[direction]
                if state.global_mode is not FaultAction.NORMAL:
                    label = f"{state.global_mode.value} ALL"
                else:
                    modes = []
                    if state.application_mode is not FaultAction.NORMAL:
                        modes.append(f"{state.application_mode.value} APPLICATION")
                    if state.admin_mode is not FaultAction.NORMAL:
                        modes.append(f"{state.admin_mode.value} ADMIN")
                    if state.delay_enabled:
                        modes.append(
                            f"DELAY {state.delay_category.value} {state.delay_ms}ms"
                        )
                    label = ", ".join(modes) if modes else "NORMAL"
                parts.append(f"{direction} {label}")
            active_rules = sum(rule.enabled for rule in self._rules)
            suffix = f" | {active_rules} active rule(s) | {paused_count} paused"
            if self._one_shots:
                suffix += f" | {len(self._one_shots)} one-shot armed"
            return " | ".join(parts) + suffix

    def _decision_for_action(
        self,
        action: FaultAction,
        delay_ms: int,
        jitter_ms: int,
        duplicate_copies: int,
        *,
        matched_rule: str = "",
        reason: str,
    ) -> FaultDecision:
        actual_delay = 0
        copies = 0
        if action is FaultAction.DELAY:
            actual_delay = max(0, int(delay_ms) + self._random.randint(-int(jitter_ms), int(jitter_ms)))
        elif action is FaultAction.DUPLICATE:
            copies = max(1, min(MAX_DUPLICATE_COPIES, int(duplicate_copies)))
        return FaultDecision(action, actual_delay, copies, matched_rule, reason)

    @staticmethod
    def _matches(rule: FaultRule, direction: str, category: MessageCategory, message) -> bool:
        if rule.direction not in {"ANY", direction}:
            return False
        if rule.msg_type and rule.msg_type != message.msg_type:
            return False
        if rule.category not in {MessageCategory.ANY, category}:
            return False
        for condition in rule.conditions:
            if not any(
                field.tag == condition.tag
                and bytes(field.value).decode(message.encoding, errors="replace") == condition.value
                for field in message.fields
            ):
                return False
        return True

    def _rule_index(self, rule_id: int) -> int:
        for index, rule in enumerate(self._rules):
            if rule.rule_id == int(rule_id):
                return index
        raise KeyError(f"Unknown proxy behaviour rule: {rule_id}")

    @staticmethod
    def _validate_direction(direction: str) -> None:
        if direction not in DIRECTIONS:
            raise ValueError(f"Unknown FIX direction: {direction}")

    @staticmethod
    def _coerce_action(action: FaultAction | str) -> FaultAction:
        return action if isinstance(action, FaultAction) else FaultAction(str(action).upper())

    @staticmethod
    def _coerce_category(category: MessageCategory | str) -> MessageCategory:
        return category if isinstance(category, MessageCategory) else MessageCategory(str(category).upper())

    @staticmethod
    def _bounded_delay(value: int, label: str) -> int:
        result = int(value)
        if not 0 <= result <= MAX_DELAY_MS:
            raise ValueError(f"{label} must be between 0 and {MAX_DELAY_MS} ms")
        return result


__all__ = [
    "DIRECTIONS",
    "MAX_DELAY_MS",
    "MAX_DUPLICATE_COPIES",
    "MAX_ONE_SHOT_MESSAGES",
    "DirectionBehaviour",
    "DisconnectEvent",
    "DisconnectSide",
    "DisconnectTrigger",
    "FaultAction",
    "FaultDecision",
    "FaultEvent",
    "FaultRule",
    "MessageCategory",
    "OneShotAction",
    "ProxyBehaviourController",
    "ProxyBehaviourSnapshot",
    "TagCondition",
]
