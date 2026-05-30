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
import attr
from typing import Any, Dict, List, Set

ConfigDict = Dict[str, Any]

def check_all_permissions_understood(permissions: List[str]) -> None:
    """
    Checks that all the permissions contained in the list of permissions are
    ones that we understand and recognise.
    """
    for permission in permissions:
        if permission not in ALL_UNDERSTOOD_PERMISSIONS:
            nice_list_of_understood_permissions = ", ".join(
                sorted(ALL_UNDERSTOOD_PERMISSIONS)
            )
            raise ValueError(
                f"{permission!r} is not a permission recognised "
                f"by the User Restrictions module; "
                f"try one of: {nice_list_of_understood_permissions}"
            )

def check_list_elements_are_strings(
    input: List[Any], failure_message: str
) -> List[str]:
    """
    Checks that all elements in a list are of the specified type, casting it upon
    success.
    """
    for ele in input:
        if not isinstance(ele, str):
            raise ValueError(failure_message)

    return input  # type: ignore


@attr.s(auto_attribs=True, frozen=True, slots=True)
class UserRestrictionsModuleConfig:
    """
    The root-level configuration.
    """
    local_homeserver: str
    friendly_homeservers: Set[str]
    friendly_admins: Set[str]          # full MXIDs granted invite_all
    user_privileges: Dict[str, Set[str]]  # local username -> allowed permissions
    default_deny: Set[str]
    blacklisted_users: Set[str]
    blacklisted_servers: Set[str]
    greylisted_users: Set[str]
    greylisted_servers: Set[str]

    @staticmethod
    def from_config(config_dict: ConfigDict) -> "UserRestrictionsModuleConfig":
        # local_homeserver (single, required)
        local_hs = config_dict.get("local_homeserver")
        if local_hs is None or not isinstance(local_hs, str):
            raise ValueError("'local_homeserver' must be specified as a string.")
        local_homeserver = local_hs.lower()

        # friendly_homeservers
        friendly = config_dict.get("friendly_homeservers")
        if friendly is None:
            raise ValueError("'friendly_homeservers' must be specified.")
        if not isinstance(friendly, list):
            raise ValueError("'friendly_homeservers' should be a list.")
        friendly_list = check_list_elements_are_strings(
            friendly, "'friendly_homeservers' should be a list of strings."
        )
        friendly_homeservers = {hs.lower() for hs in friendly_list}

        # friendly_admins - full MXIDs that get invite_all permission
        friendly_admins_raw = config_dict.get("friendly_admins", [])
        if not isinstance(friendly_admins_raw, list):
            raise ValueError("'friendly_admins' should be a list.")
        friendly_admins_list = check_list_elements_are_strings(
            friendly_admins_raw, "'friendly_admins' should be a list of strings."
        )
        friendly_admins_set = set(friendly_admins_list)

        # rules - username lists only (local users)
        rules = config_dict.get("rules", [])
        if not isinstance(rules, list):
            raise ValueError("'rules' should be a list.")

        user_privileges: Dict[str, Set[str]] = {}
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ValueError(
                    f"Rules should be dicts. "
                    f"Rule number {index + 1} is not (found: {type(rule).__name__})."
                )
            match = rule.get("match")
            if not isinstance(match, list):
                raise ValueError(f"Rule number {index + 1}: 'match' field must be a list of usernames.")
            match_list = check_list_elements_are_strings(
                match, f"Rule number {index + 1}: 'match' field must be a list of strings."
            )

            allow = rule.get("allow", [])
            if not isinstance(allow, list):
                raise ValueError(f"Rule number {index + 1}: 'allow' field must be a list.")
            allow_list = check_list_elements_are_strings(
                allow, f"Rule number {index + 1}: 'allow' field must be a list of strings."
            )
            check_all_permissions_understood(allow_list)

            allow_set = set(allow_list)
            for username in match_list:
                if username in user_privileges:
                    user_privileges[username] |= allow_set
                else:
                    user_privileges[username] = allow_set.copy()

        # default_deny (local users only)
        default_deny = config_dict.get("default_deny", [])
        if not isinstance(default_deny, list):
            raise ValueError("'default_deny' should be a list.")
        default_deny_list = check_list_elements_are_strings(
            default_deny, "'default_deny' should be a list of strings."
        )
        check_all_permissions_understood(default_deny_list)
        default_deny_set = set(default_deny_list)

        # blacklisted / greylisted - unchanged
        blacklisted_users = config_dict.get("blacklisted_users", [])
        if not isinstance(blacklisted_users, list):
            raise ValueError("'blacklisted_users' should be a list.")
        blacklisted_users_list = check_list_elements_are_strings(
            blacklisted_users, "'blacklisted_users' should be a list of strings."
        )
        blacklisted_users_set = set(blacklisted_users_list)

        blacklisted_servers = config_dict.get("blacklisted_servers", [])
        if not isinstance(blacklisted_servers, list):
            raise ValueError("'blacklisted_servers' should be a list.")
        blacklisted_servers_list = check_list_elements_are_strings(
            blacklisted_servers, "'blacklisted_servers' should be a list of strings."
        )
        blacklisted_servers_set = {hs.lower() for hs in blacklisted_servers_list}

        greylisted_users = config_dict.get("greylisted_users", [])
        if not isinstance(greylisted_users, list):
            raise ValueError("'greylisted_users' should be a list.")
        greylisted_users_list = check_list_elements_are_strings(
            greylisted_users, "'greylisted_users' should be a list of strings."
        )
        greylisted_users_set = set(greylisted_users_list)

        greylisted_servers = config_dict.get("greylisted_servers", [])
        if not isinstance(greylisted_servers, list):
            raise ValueError("'greylisted_servers' should be a list.")
        greylisted_servers_list = check_list_elements_are_strings(
            greylisted_servers, "'greylisted_servers' should be a list of strings."
        )
        greylisted_servers_set = {hs.lower() for hs in greylisted_servers_list}

        return UserRestrictionsModuleConfig(
            local_homeserver=local_homeserver,
            friendly_homeservers=friendly_homeservers,
            friendly_admins=friendly_admins_set,
            user_privileges=user_privileges,
            default_deny=default_deny_set,
            blacklisted_users=blacklisted_users_set,
            blacklisted_servers=blacklisted_servers_set,
            greylisted_users=greylisted_users_set,
            greylisted_servers=greylisted_servers_set,
        )


INVITE = "invite"
CREATE_ROOM = "create_room"
RECEIVE_INVITES = "receive_invites"
RECEIVE_ALL_INVITES = "receive_all_invites"
INVITE_ALL = "invite_all"
JOIN_ROOM = "join_room"
ALL_UNDERSTOOD_PERMISSIONS = frozenset({
    INVITE, CREATE_ROOM, RECEIVE_INVITES, RECEIVE_ALL_INVITES, INVITE_ALL, JOIN_ROOM
})
