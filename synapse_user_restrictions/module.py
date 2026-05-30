# Copyright 2021 The Matrix.org Foundation C.I.C.
# Copyright 2026 sync85968211
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from synapse.module_api import ModuleApi
from synapse.module_api.errors import ConfigError
from synapse.api.errors import SynapseError, Codes
import logging
logger = logging.getLogger(__name__)

from synapse_user_restrictions.config import (
    ALL_UNDERSTOOD_PERMISSIONS,
    CREATE_ROOM,
    INVITE,
    RECEIVE_INVITES,
    RECEIVE_ALL_INVITES,
    INVITE_ALL,
    JOIN_ROOM,
    UserRestrictionsModuleConfig,
)

class UserRestrictionsModule:
    def __init__(self, config: UserRestrictionsModuleConfig, api: ModuleApi):
        self._api = api
        self._config = config

        api.register_spam_checker_callbacks(
            user_may_create_room=self.callback_user_may_create_room,
            user_may_invite=self.callback_user_may_invite,
            user_may_join_room=self.callback_user_may_join_room,
        )

    @staticmethod
    def parse_config(config: dict) -> UserRestrictionsModuleConfig:
        try:
            return UserRestrictionsModuleConfig.from_config(config)
        except (TypeError, ValueError) as e:
            raise ConfigError(f"Failed to parse user restrictions module config: {e}")

    def _get_domain(self, user_id: str) -> str:
        """Extract the domain part of a Matrix user ID and normalize to lowercase."""
        return user_id.split(":", 1)[1].lower()

    def _is_blacklisted(self, user_id: str) -> bool:
        """Check if a user or their server is blacklisted (blocks invites both ways)."""
        if user_id in self._config.blacklisted_users:
            return True
        domain = self._get_domain(user_id)
        return domain in self._config.blacklisted_servers

    def _is_greylisted(self, user_id: str) -> bool:
        """Check if a user or their server is greylisted (blocks only invites from them)."""
        if user_id in self._config.greylisted_users:
            return True
        domain = self._get_domain(user_id)
        return domain in self._config.greylisted_servers

    def _is_local_user(self, user_id: str) -> bool:
        """Check if user belongs to our primary local homeserver."""
        return self._get_domain(user_id) == self._config.local_homeserver

    def _get_local_username(self, user_id: str) -> str | None:
        """Return the localpart if user is on local_homeserver, else None."""
        if not self._is_local_user(user_id):
            return None
        return user_id[1:].split(":", 1)[0]

    def _has_permission(self, user_id: str, permission: str) -> bool:
        """
        Pure permission check that always returns True/False.
        Never raises errors (used for internal checks like inviters).
        """
        if permission not in ALL_UNDERSTOOD_PERMISSIONS:
            return False

        # Friendly admins always get invite_all
        if permission == INVITE_ALL and user_id in self._config.friendly_admins:
            return True

        # Local users use the prebuilt privileges map
        username = self._get_local_username(user_id)
        if username is None:
            # Foreign users: only invite_all is restricted
            return permission != INVITE_ALL

        # Local user path
        allowed_perms = self._config.user_privileges.get(username, set())
        if permission in allowed_perms:
            return True

        if permission in self._config.default_deny:
            return False

        return True

    def _apply_rules(self, user_id: str, permission: str) -> bool:
        """
        Permission checker that raises custom error messages for local users.
        """
        if self._has_permission(user_id, permission):
            return True

        # Local user denied → raise custom message
        messages = {
            INVITE: "You do not have permission to invite other users.",
            CREATE_ROOM: "You are not allowed to create new rooms.",
            JOIN_ROOM: "You do not have permission to join rooms.",
            RECEIVE_INVITES: "You are not allowed to receive invites from external servers.",
            RECEIVE_ALL_INVITES: "You are not allowed to receive invites.",
            INVITE_ALL: "You do not have permission to invite anyone.",
        }

        msg = messages.get(permission, "This action is restricted by server policy.")
        raise SynapseError(403, msg, errcode=Codes.FORBIDDEN)

    async def callback_user_may_create_room(self, user: str) -> bool:
        return self._apply_rules(user, CREATE_ROOM)

    async def callback_user_may_invite(
        self, inviter: str, invitee: str, room_id: str
    ) -> bool:
        # Blacklist checks (blocks invites both to and from these users/servers)
        if self._is_blacklisted(inviter) or self._is_blacklisted(invitee):
            return False

        # Greylist checks (blocks only invites from these users/servers)
        if self._is_greylisted(inviter):
            return False

        # Inviter must have basic invite permission
        if not self._apply_rules(inviter, INVITE):
            return False

        # Inviter with invite_all bypasses all invitee checks
        if self._has_permission(inviter, INVITE_ALL):
            return True

        # Invitee with receive_all_invites accepts from any server
        if self._has_permission(invitee, RECEIVE_ALL_INVITES):
            return True

        # Invitee with receive_invites accepts only from friendly_homeservers
        if self._has_permission(invitee, RECEIVE_INVITES):
            inviter_domain = self._get_domain(inviter)
            return inviter_domain in self._config.friendly_homeservers

        # Otherwise denied
        return False

    async def _user_is_already_joined(self, user: str, room_id: str) -> bool:
        """Return True if the user is currently joined to the room.
        This distinguishes profile updates (treated internally as 'join')
        from genuine new-join attempts, so JOIN_ROOM restrictions apply
        only to the latter while profile changes always propagate.
        """
        try:
            state = await self._api.get_room_state(
                room_id, [("m.room.member", user)]
            )
            member_event = state.get(("m.room.member", user))
            if member_event:
                membership = member_event.content.get("membership")
                if membership == "join":
                    return True
        except Exception as e:
            # Room not found, no permission to read state, etc. Treat as not joined
            # (safe fallback; new-join attempt will still be subject to rules).
            logger.debug(f"Failed to get membership for {user} in {room_id}: {e}")
        return False

    async def callback_user_may_join_room(self, user: str, room_id: str, is_invited: bool) -> bool:
        logger.info(f"Checking {user} for {room_id}, is_invited={is_invited}")

        if await self._user_is_already_joined(user, room_id):
            logger.info(f"Allowing {user} to 'join' {room_id} (profile update - already joined)")
            return True

        if is_invited:
            # The invite was already approved by callback_user_may_invite()
            # (which already verified the inviter has invite_all / is a friendly_admin,
            # the invitee can receive it, blacklist/greylist checks, etc.).
            # Therefore we allow acceptance even if the invitee lacks join_room permission.
            # This fixes the remote friendly_admin case reliably (no state lookup needed).
            logger.info(f"Allowing {user} to join {room_id} (invited - join_room restriction bypassed)")
            return True

        # Not an invited join and not already joined → enforce join_room permission
        # (raises the friendly error message for local users)
        return self._apply_rules(user, JOIN_ROOM)
