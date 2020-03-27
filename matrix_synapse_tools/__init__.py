import re
import time
import json
import sys

import requests

from copy import deepcopy
from argparse import ArgumentParser
from urllib.parse import urljoin
from urllib.parse import quote as _quote

from ldap3 import Connection
from requests_toolbelt import sessions
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


def quote(string):
    return _quote(string, safe="@")


def merge_json(jdefault, jin):
    jout = deepcopy(jdefault)
    for key in jin:
        if key in jout and isinstance(jin[key], dict):
            jout[key] = merge_json(jdefault[key], jin[key])
        else:
            jout[key] = jin[key]
    return jout


class MatrixSynapseToolsError(Exception):
    pass


class MatrixRequestError(Exception):
    def __init__(self, http_error, message):
        super(MatrixRequestError, self).__init__(message)
        self.http_error = http_error


class MConnection:
    endpoints = {
        "list_users": "/_synapse/admin/v2/users?from=0&guests=false",
        "query_user": "/_synapse/admin/v2/users/{user_id}",
        "create_room": "/_matrix/client/r0/createRoom",
        "create_group": "/_matrix/client/r0/create_group",
        "groups_of_room": "/_matrix/client/r0/rooms/{room_id}/state/m.room.related_groups/",
        "rooms_to_group": "/_matrix/client/r0/groups/{group_id}/admin/rooms/{room_id}",
        "rooms_of_group": "/_matrix/client/r0/groups/{group_id}/rooms",
        "server_notice": "/_synapse/admin/v1/send_server_notice",
    }
    username_regex = r"@(?P<username>[a-z0-9._=\-\/]+):"

    def __init__(self, address, servername, token, *, maxretries=5):
        self.address = address
        self.servername = servername
        self.auth_header = {"Authorization": f"Bearer {token}"}
        self._maxretries = maxretries

        self.user_regex = re.compile(self.username_regex + re.escape(servername))

        # set a default base for the url
        self.session = sessions.BaseUrlSession(base_url=address)
        # set auth_header as default
        self.session.headers.update(self.auth_header)
        # check non 4XX or 5XX status code on each response
        self.session.hooks["response"] = [
            lambda response, *args, **kwargs: response.raise_for_status()
        ]

    def _get(self, endpoint, message, *args, **kwargs):
        for i in range(self._maxretries):
            try:
                req = self.session.get(endpoint, *args, **kwargs)
                break
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    time.sleep(e.response.json()["retry_after_ms"] / 1000)
                else:
                    raise MatrixRequestError(
                        e,
                        message
                        + f" Status: {e.response.status_code},Reason:{e.response.reason}",
                    )
        return req

    def _post(self, endpoint, message, *args, **kwargs):
        for i in range(self._maxretries):
            try:
                req = self.session.post(endpoint, *args, **kwargs)
                break
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    time.sleep(e.response.json()["retry_after_ms"] / 1000)
                else:
                    raise MatrixRequestError(
                        e,
                        message
                        + f" Status: {e.response.status_code},Reason:{e.response.reason}",
                    )
        return req

    def _put(self, endpoint, message, *args, **kwargs):
        for i in range(self._maxretries):
            try:
                req = self.session.put(endpoint, *args, **kwargs)
                break
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    time.sleep(e.response.json()["retry_after_ms"] / 1000)
                else:
                    raise MatrixRequestError(
                        e,
                        message
                        + f" Status: {e.response.status_code},Reason:{e.response.reason}",
                    )
        return req

    def user_id(self, username):
        return f"@{username}:{self.servername}"

    def group_id(self, groupname):
        return f"+{groupname}:{self.servername}"

    def get_matrix_users(self):
        req = self._get(self.endpoints["list_users"], "Failed to fetch userlist.")
        user_ids = [
            userdic["name"]
            for userdic in req.json()["users"]
            if not userdic["deactivated"]
        ]
        users = []
        for user_id in user_ids:
            match = self.user_regex.search(user_id)
            if match:
                users.append(match.group("username"))
        return users

    def query_matrix_user(self, user_id):
        req = self._get(
            self.endpoints["query_user"].format(user_id=quote(user_id)),
            "Failed to query user.",
        )
        return req.json()

    def last_seen_user(self, user_id):
        query = self.query_matrix_user(user_id)
        last_seen = max(
            [
                connection["last_seen"]
                for device in query["devices"].values()
                for session in device["sessions"]
                for connection in session["connections"].values()
            ]
        )
        return last_seen

    def get_groups_of_room(self, room_id):
        try:
            req = self._get(
                self.endpoints["groups_of_room"].format(room_id=quote(room_id)),
                "Failed to get groups of room.",
            )
            return req.json()["groups"]
        except MatrixRequestError as e:
            if e.http_error.response.status_code == 404:
                return []
            else:
                raise MatrixRequestError(
                    e,
                    f"Failed to get groups of room. Status: {e.request.status_code}, Reason:{e.request.reason}",
                )

    def get_rooms_of_group(self, group_id):
        req = self._get(
            self.endpoints["rooms_of_group"].format(group_id=quote(group_id)),
            "Failed to get rooms of group.",
        )
        return [room["room_id"] for room in req.json()["chunk"]]

    def create_room(self, room_params):
        req = self._post(
            self.endpoints["create_room"],
            "Failed to create room.",
            headers={"Content-Type": "application/json"},
            json=room_params,
        )
        return req.json()["room_id"]

    def create_group(self, group_params):
        req = self._post(
            self.endpoints["create_group"],
            "Failed to create group.",
            headers={"Content-Type": "application/json"},
            json=group_params,
        )
        return req.json()["group_id"]

    def add_room_to_group(self, group_id, room_id, visibility):
        req = self._put(
            self.endpoints["rooms_to_group"].format(
                group_id=quote(group_id), room_id=quote(room_id),
            ),
            "Failed to add room to group.",
            headers={**self.auth_header, "Content-Type": "application/json",},
            json={"m.visibility": {"type": visibility}},
        )

        old_groups = self.get_groups_of_room(room_id)
        if group_id not in old_groups:
            req = self._put(
                self.endpoints["groups_of_room"].format(room_id=quote(room_id)),
                "Failed to add group to room.",
                headers={**self.auth_header, "Content-Type": "application/json",},
                json={"groups": old_groups + [group_id]},
            )

    def send_server_notice(self, message, user_ids=None):
        if user_ids is None:
            user_ids = [self.user_id(user) for user in self.get_matrix_users()]
        for user_id in user_ids:
            self._post(
                self.endpoints["server_notice"],
                "Failed to send server notice",
                json={
                    "user_id": user_id,
                    "content": {"msgtype": "m.text", "body": message},
                },
            )


def send_notice(matrix_connection, args):
    matrix_connection.send_server_notice(args.message, user_ids=args.users)


def main():
    parser = ArgumentParser(
        description="Generate policy for matrix-corporal from ldap."
    )
    parser.add_argument(
        "-c",
        "--configfile",
        help="""config json setting server_address,
    server_name and auth token""",
    )
    parser.add_argument(
        "-a",
        "--address",
        help="""Address of the synaspse server with protocol.
                e.g. http://localhost:8008 or https://matrix.myhomeserver.org""",
        default=None,
    )
    parser.add_argument(
        "-s",
        "--servername",
        help="""Servername of your server. The part of the user id after the colon""",
        default=None,
    )
    parser.add_argument(
        "-t", "--token", help="""Access token of an admin user""", default=None,
    )
    subparsers = parser.add_subparsers(help="Actions on the synapse server")
    notice_parser = subparsers.add_parser("server_notice", help="Send a server notice",)
    notice_parser.add_argument("message", help="Message to send as server notice")
    notice_parser.add_argument(
        "-u" "--users",
        help="""
    A comma separated list of full user ids;
    If ommited the message will be sent to all users on the server.""",
        default=None,
    )
    notice_parser.set_defaults(func=send_notice)
    args = parser.parse_args()
    if args.configfile:
        with open(args.configfile, "r") as f:
            config = json.load(f)
    elif all((args.address, args.servername, args.token)):
        config = {"server_address": args.address,
                  "server_name": args.servername,
                  "access_token": args.token}
    else:
        raise MatrixSynapseToolsError(
            "Either specify config file or give address, servername and token"
        )
    matrix_connection = MConnection(
        config["server_address"], ["server_name"], ["access_token"]
    )
    args.func(matrix_connection, args)


if __name__ == "__main__":
    main()
