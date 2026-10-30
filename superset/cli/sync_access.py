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

"""Reconcile database access permissions onto roles."""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

import click
import yaml
from flask.cli import with_appcontext

from superset import db, security_manager
from superset.models.core import Database

logger = logging.getLogger(__name__)

MANAGED_PERMISSIONS = {
    "database_access",
    "database_dataset_access",
}

ACCESS_PERMISSIONS = {
    "datasets": "database_dataset_access",
    "database": "database_access",
}


def _pvm_key(pvm: Any) -> tuple[str, str]:
    return pvm.permission.name, pvm.view_menu.name


def _load_config(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    if not isinstance(config, dict):
        raise click.ClickException("Access config must be a YAML mapping")
    if "roles" in config:
        raise click.ClickException(
            "Role-first access config is no longer supported; use top-level "
            "'databases' keyed by database name"
        )
    databases = config.get("databases") or {}
    if not isinstance(databases, dict):
        raise click.ClickException("Access config 'databases' must be a mapping")
    if "datasets" in config:
        raise click.ClickException(
            "Top-level 'datasets' is not supported; define dataset access "
            "under a database entry"
        )
    return config


def _resolve_database(name: str) -> Database:
    database = (
        db.session.query(Database).filter(Database.database_name == name).one_or_none()
    )
    if not database:
        raise click.ClickException(f"Database not found: {name}")
    return database


def _resolve_pvm(permission_name: str, view_name: str, label: str) -> Any:
    pvm = security_manager.find_permission_view_menu(permission_name, view_name)
    if not pvm:
        raise click.ClickException(f"Permission not found for {label}")
    return pvm


def _role_names(roles: Any, label: str) -> list[str]:
    if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
        raise click.ClickException(f"{label} must be a list of role names")
    return roles


def _add_database_permissions(
    desired: dict[str, dict[tuple[str, str], Any]],
    name: str,
    spec: dict[str, Any],
) -> None:
    unknown = set(spec) - set(ACCESS_PERMISSIONS)
    if unknown:
        raise click.ClickException(
            f"Unknown access key(s) for {name}: {', '.join(sorted(unknown))}"
        )
    modes = {mode: spec[mode] for mode in ACCESS_PERMISSIONS if mode in spec}
    if not modes:
        raise click.ClickException(
            f"Database entry must define 'datasets' and/or 'database': {name}"
        )

    database = _resolve_database(name)
    database_perm = database.perm
    if not database_perm:
        raise click.ClickException(
            f"Database has no permission string: {database.database_name}"
        )

    for mode, roles in modes.items():
        permission_name = ACCESS_PERMISSIONS[mode]
        pvm = _resolve_pvm(
            permission_name,
            str(database_perm),
            f"database {database.database_name} ({mode})",
        )
        for role_name in _role_names(roles, f"{database.database_name}.{mode}"):
            desired[role_name][_pvm_key(pvm)] = pvm


def _desired_permissions(
    config: dict[str, Any],
) -> dict[str, dict[tuple[str, str], Any]]:
    desired: dict[str, dict[tuple[str, str], Any]] = defaultdict(dict)

    for name, spec in (config.get("databases") or {}).items():
        if not isinstance(spec, dict):
            raise click.ClickException(f"Database entry must be a mapping: {name}")
        _add_database_permissions(desired, str(name), spec)

    return dict(desired)


def _sync_role(
    role_name: str,
    desired: dict[tuple[str, str], Any],
) -> tuple[int, int]:
    role = security_manager.find_role(role_name)
    if not role:
        raise click.ClickException(f"Role not found: {role_name}")

    current = {
        _pvm_key(pvm): pvm
        for pvm in role.permissions
        if pvm.permission.name in MANAGED_PERMISSIONS
    }

    added = 0
    for key, pvm in desired.items():
        if key not in current:
            security_manager.add_permission_role(role, pvm)
            added += 1

    removed = 0
    for key, pvm in current.items():
        if key not in desired:
            security_manager.del_permission_role(role, pvm)
            removed += 1

    return added, removed


@click.command(name="sync_access")
@with_appcontext
@click.option(
    "--path",
    "-p",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="YAML file mapping database names to access modes and roles.",
)
def sync_access(path: Path) -> None:
    """Reconcile database access onto all roles.

    The config is the full desired grant set for managed database PVMs. Roles
    missing from the config lose those PVMs; user membership is never changed.
    """
    config = _load_config(path)
    desired_by_role = _desired_permissions(config)

    roles = security_manager.get_all_roles()
    role_names = {role.name for role in roles}
    missing = set(desired_by_role) - role_names
    if missing:
        raise click.ClickException(f"Role not found: {', '.join(sorted(missing))}")

    added_total = 0
    removed_total = 0
    for role in roles:
        if role.name == security_manager.auth_role_admin:
            continue
        desired = desired_by_role.get(role.name, {})
        added, removed = _sync_role(role.name, desired)
        added_total += added
        removed_total += removed
        if added or removed:
            click.echo(f"{role.name}: {added} added, {removed} removed")

    click.echo(f"Access sync complete: {added_total} added, {removed_total} removed")
