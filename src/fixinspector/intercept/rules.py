"""Application/admin interception policy independent of transport."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class InterceptPolicy:
    hold_client_to_server: bool = False
    hold_server_to_client: bool = False
    hold_client_to_server_admin: bool = False
    hold_server_to_client_admin: bool = False

    def should_hold(self, direction: str, msg_type: str, dictionary) -> bool:
        is_admin = dictionary.is_admin(msg_type)
        if direction == "C→S":
            enabled = (
                self.hold_client_to_server_admin if is_admin else self.hold_client_to_server
            )
        else:
            enabled = (
                self.hold_server_to_client_admin if is_admin else self.hold_server_to_client
            )
        return bool(enabled)
