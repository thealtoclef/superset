# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Reconcile FAB roles from declarative configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click
import yaml
from flask import current_app
from flask.cli import with_appcontext

from superset import db, security_manager
from superset.daos.role import RoleDAO

BUILTIN_ROLES = frozenset({"Admin", "Alpha", "Gamma", "Public", "sql_lab"})
ROLE_NAME_MAX_LENGTH = 64


def _role_names(value: Any, label: str) -> set[str]:
    if isinstance(value, dict):
        names = list(value)
    elif isinstance(value, list):
        names = value
    else:
        raise click.ClickException(f"{label} must be a list or mapping of role names")

    result: set[str] = set()
    for name in names:
        if not isinstance(name, str) or not name.strip():
            raise click.ClickException(f"{label} contains an invalid role name")
        name = name.strip()
        if len(name) > ROLE_NAME_MAX_LENGTH:
            raise click.ClickException(
                f"Role name exceeds {ROLE_NAME_MAX_LENGTH} characters: {name}"
            )
        if name in result:
            raise click.ClickException(f"Duplicate role name in {label}: {name}")
        result.add(name)
    return result


def _load_config(path: Path) -> tuple[set[str], set[str]]:
    with path.open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    if not isinstance(config, dict):
        raise click.ClickException("Role config must be a YAML mapping")
    unknown = set(config) - {"roles", "protected_roles"}
    if unknown:
        raise click.ClickException(
            f"Unknown role config key(s): {', '.join(sorted(unknown))}"
        )
    if "roles" not in config:
        raise click.ClickException("Role config has no 'roles' key")

    roles = _role_names(config["roles"], "roles")
    protected = (
        _role_names(config["protected_roles"], "protected_roles")
        if "protected_roles" in config
        else set()
    )
    return roles, protected


def _add_config_names(names: set[str], value: Any) -> None:
    if isinstance(value, str):
        if value.strip():
            names.add(value.strip())
    elif isinstance(value, (list, tuple, set)):
        names.update(
            item.strip() for item in value if isinstance(item, str) and item.strip()
        )


def _config_referenced_roles() -> set[str]:
    """Return every role name referenced by Superset/FAB auth configuration."""
    names: set[str] = set()
    for attribute in (
        "auth_role_admin",
        "auth_role_public",
        "auth_user_registration_role",
    ):
        _add_config_names(names, getattr(security_manager, attribute, None))

    for key in (
        "AUTH_ROLE_ADMIN",
        "AUTH_ROLE_PUBLIC",
        "AUTH_USER_REGISTRATION_ROLE",
        "PUBLIC_ROLE_LIKE",
    ):
        _add_config_names(names, current_app.config.get(key))

    static_mapping = current_app.config.get("AUTH_STATIC_ROLE_MAPPING")
    if isinstance(static_mapping, dict):
        _add_config_names(names, list(static_mapping))

    roles_mapping = current_app.config.get("AUTH_ROLES_MAPPING")
    if isinstance(roles_mapping, dict):
        for value in roles_mapping.values():
            _add_config_names(names, value)

    return names


def _sync_roles(desired: set[str], protected: set[str]) -> tuple[int, int]:
    roles = {role.name: role for role in security_manager.get_all_roles()}
    created = 0

    try:
        for name in sorted(desired):
            if name in roles:
                continue
            # Built-in roles are populated by `superset init`; do not create an
            # empty placeholder before that command runs.
            if name in BUILTIN_ROLES:
                continue
            RoleDAO.create(attributes={"name": name})
            created += 1

        roles = {role.name: role for role in security_manager.get_all_roles()}
        deleted = 0
        for name, role in sorted(roles.items()):
            if name in protected:
                continue
            RoleDAO.delete([role])
            deleted += 1

        db.session.commit()
    except Exception as ex:
        db.session.rollback()
        raise click.ClickException(f"Role sync failed: {ex}") from ex

    return created, deleted


@click.command(name="sync_roles")
@with_appcontext
@click.option(
    "--path",
    "-p",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="YAML file listing the desired roles.",
)
def sync_roles(path: Path) -> None:
    """Create declared roles and delete unmanaged non-built-in roles.

    The role file, roles referenced by Superset auth configuration, and the
    built-in roles are kept. Every other role is deleted, including roles still
    assigned to users or referenced by dashboards and RLS subjects.
    """
    roles, protected = _load_config(path)
    referenced = _config_referenced_roles()
    desired = roles | referenced | set(BUILTIN_ROLES)

    created, deleted = _sync_roles(desired, desired | protected)
    click.echo(f"Role sync complete: {created} created, {deleted} deleted")
