"""Read/write UI projection of existing fault policy; no routing/matching engine."""

from dataclasses import dataclass

from ...intercept.proxy_behaviour import FaultAction, MessageCategory
from ...presentation import display_direction


@dataclass(frozen=True)
class RuleRow:
    key: tuple
    priority: str
    enabled: bool
    direction: str
    match: str
    action: str
    summary: str
    editable: bool = True


class RulesAdapter:
    def __init__(self, engine, policy_provider):
        self.engine = engine
        self.controller = engine.proxy_behaviour
        self.policy_provider = policy_provider

    def rows(self):
        snapshot = self.controller.snapshot()
        rows = []
        policy = self.policy_provider()
        for direction, state in (("C→S", snapshot.client_to_server), ("S→C", snapshot.server_to_client)):
            if state.global_mode is not FaultAction.NORMAL:
                rows.append(RuleRow(("global", direction), "1", True, direction, "All messages", state.global_mode.value, "Global override"))
            shot = snapshot.one_shots.get(direction)
            if shot:
                rows.append(RuleRow(("once", direction), "2", True, direction, "All messages", shot.action.value,
                                    f"Next {shot.remaining} · {self.parameters(shot)}"))
        for order, rule in enumerate(snapshot.rules, 1):
            category = {MessageCategory.ANY: "All messages", MessageCategory.APPLICATION: "Application", MessageCategory.ADMIN: "Session/Admin"}[rule.category]
            parts = [category]
            if rule.msg_type:
                parts.append(f"MsgType={rule.msg_type}")
            parts.extend(f"{condition.tag}={'<REDACTED>' if condition.tag in policy.secret_tags else condition.value}" for condition in rule.conditions)
            rows.append(RuleRow(("rule", rule.rule_id), f"3.{order}", rule.enabled, rule.direction,
                                policy.redact_text(" AND ".join(parts)), rule.action.value,
                                policy.redact_text(f"{rule.name} · {self.parameters(rule)}")))
        for direction, state in (("C→S", snapshot.client_to_server), ("S→C", snapshot.server_to_client)):
            for category, action in (("APPLICATION", state.application_mode), ("ADMIN", state.admin_mode)):
                if action is not FaultAction.NORMAL:
                    rows.append(RuleRow(("category", direction, category), "4", True, direction,
                                        "Application" if category == "APPLICATION" else "Session/Admin", action.value, "Category default"))
            if state.delay_enabled:
                rows.append(RuleRow(("delay", direction), "5", True, direction, state.delay_category.value,
                                    "DELAY", f"Direction delay · {state.delay_ms} ms ± {state.jitter_ms} ms"))
        for trigger in snapshot.disconnect_triggers:
            rows.append(RuleRow(("disconnect", trigger.trigger_id), "Event", True, trigger.direction, "All messages",
                                "DISCONNECT", f"{trigger.side.value} after {trigger.remaining} {trigger.event.value} · independent trigger", False))
        return sorted(rows, key=lambda row: (row.priority.split('.')[0], int(row.priority.split('.')[1]) if '.' in row.priority else 0))

    @staticmethod
    def parameters(item):
        if item.action is FaultAction.DELAY:
            return f"{item.delay_ms} ms ± {item.jitter_ms} ms"
        if item.action is FaultAction.DUPLICATE:
            return f"{item.duplicate_copies} extra copies"
        return item.action.value.title()

    def disable_or_delete(self, row, *, delete=False):
        kind, key, *rest = row.key
        if kind == "rule":
            if delete:
                self.controller.delete_rule(key)
            else:
                self.controller.set_rule_enabled(key, False)
        elif kind == "global":
            self.controller.set_global_mode(key, "NORMAL")
        elif kind == "category":
            self.controller.set_category_mode(key, rest[0], "NORMAL")
        elif kind == "delay":
            state = self.controller.direction(key)
            self.controller.set_delay(key, enabled=False, delay_ms=state.delay_ms,
                                      jitter_ms=state.jitter_ms, category=state.delay_category)
        elif kind == "once":
            self.controller.clear_one_shot(key)
        else:
            raise ValueError("The engine cannot cancel an individual disconnect trigger. Use Reset proxy behaviour.")

    def set_enabled(self, row, enabled):
        if row.key[0] == "rule":
            self.controller.set_rule_enabled(row.key[1], enabled)
        elif not enabled:
            self.disable_or_delete(row)

    def move(self, row, offset):
        if row.key[0] != "rule":
            raise ValueError("Only ordered rules can move; engine precedence levels are fixed.")
        self.controller.move_rule(row.key[1], offset)

    def apply(self, values, *, row=None):
        """Each branch delegates to one existing API. No simulated rule counters."""
        values = dict(values)
        kind = values.pop("kind")
        direction = values.pop("direction")
        directions = ("C→S", "S→C") if direction == "ANY" else (direction,)
        if kind == "rule":
            if row:
                return self.controller.update_rule(row.key[1], direction=direction, **values)
            return self.controller.add_rule(direction=direction, **values)
        if kind == "disconnect_now":
            return self.engine.disconnect(values["side"])
        for current in directions:
            if kind == "global":
                self.controller.set_global_mode(current, values["action"])
            elif kind == "category":
                self.controller.set_category_mode(current, values["category"], values["action"])
            elif kind == "delay":
                self.controller.set_delay(current, **values)
            elif kind == "once":
                self.controller.arm_one_shot(current, **values)
            elif kind == "disconnect":
                self.controller.arm_disconnect(direction=current, **values)
            else:
                raise ValueError(f"Unknown UI rule kind: {kind}")

    def direction_text(self, row):
        return "Both" if row.direction == "ANY" else display_direction(row.direction)
