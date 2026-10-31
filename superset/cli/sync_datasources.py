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

"""Import datasources and prune databases absent from the config."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

import click
import yaml
from flask.cli import with_appcontext

from superset import db
from superset.commands.database.delete import DeleteDatabaseCommand
from superset.connectors.sqla.models import SqlaTable
from superset.constants import SKIP_VISIBILITY_FILTER_CLASSES
from superset.daos.report import ReportScheduleDAO
from superset.models.core import Database

logger = logging.getLogger(__name__)

_ENV_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env(raw: str) -> str:
    """Replace ${VAR} placeholders from the environment.

    Unknown variables stay literal so a missing secret fails at import time
    instead of silently becoming an empty string. Only the explicit ${VAR}
    form is expanded; a bare ``$`` is left untouched for URIs and JSON.
    """
    return _ENV_PLACEHOLDER.sub(
        lambda match: os.environ.get(match.group(1), match.group(0)),
        raw,
    )


def _expand_env_value(value: Any) -> Any:
    if isinstance(value, str):
        return _expand_env(value)
    if isinstance(value, list):
        return [_expand_env_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand_env_value(item) for key, item in value.items()}
    return value


def _database_names(config: dict[str, Any]) -> list[str]:
    databases = config["databases"]
    if not isinstance(databases, list):
        raise click.ClickException("Datasource config 'databases' must be a list")

    names: list[str] = []
    for entry in databases:
        if not isinstance(entry, dict):
            raise click.ClickException("Each database entry must be a mapping")
        name = entry.get("database_name")
        if not isinstance(name, str) or not name:
            raise click.ClickException("Each database entry needs 'database_name'")
        names.append(name)

    if len(names) != len(set(names)):
        raise click.ClickException("Duplicate database_name in datasource config")
    return names


def _load_config(path: Path) -> tuple[str, set[str]]:
    raw = path.read_text(encoding="utf-8")
    try:
        config = yaml.safe_load(raw) or {}
    except yaml.YAMLError as ex:
        raise click.ClickException(f"{path} is not valid YAML") from ex

    if not isinstance(config, dict):
        raise click.ClickException("Datasource config must be a YAML mapping")
    if "databases" not in config:
        raise click.ClickException("Datasource config has no 'databases' key")

    names = _database_names(config)
    if _ENV_PLACEHOLDER.search(raw):
        # Expand values after parsing so a secret containing YAML syntax (for
        # example ``#``, ``: `` or a newline) cannot alter the document.
        config = _expand_env_value(config)
        names = _database_names(config)
        raw = yaml.safe_dump(config, sort_keys=False)

    return raw, set(names)


def _import_config(path: Path, raw: str) -> None:
    from superset.commands.dataset.importers.v0 import (  # noqa: PLC0415
        ImportDatasetsCommand,
    )

    ImportDatasetsCommand({path.name: raw}).run()


def _dataset_ids(database_id: int) -> list[int]:
    rows = (
        db.session.query(SqlaTable.id)
        .filter(SqlaTable.database_id == database_id)
        .execution_options(**{SKIP_VISIBILITY_FILTER_CLASSES: {SqlaTable}})
        .all()
    )
    return sorted(row[0] for row in rows)


def _prune_databases(desired: set[str]) -> tuple[int, list[str]]:
    deleted = 0
    kept: list[str] = []

    for database in db.session.query(Database).all():
        if database.database_name in desired:
            continue

        dataset_ids = _dataset_ids(database.id)
        report_ids = sorted(
            report.id for report in ReportScheduleDAO.find_by_database_id(database.id)
        )
        if dataset_ids or report_ids:
            references = []
            if dataset_ids:
                references.append(f"dataset id(s) {dataset_ids}")
            if report_ids:
                references.append(f"report schedule id(s) {report_ids}")
            message = (
                f"Cannot delete database {database.database_name}: "
                f"{', '.join(references)} still reference it"
            )
            logger.error(message)
            click.echo(f"ERROR: {message}", err=True)
            kept.append(database.database_name)
            continue

        try:
            DeleteDatabaseCommand(database.id).run()
        except Exception:  # pylint: disable=broad-except
            logger.exception("Failed to delete database %s", database.database_name)
            click.echo(
                f"ERROR: failed to delete database {database.database_name}",
                err=True,
            )
            kept.append(database.database_name)
            continue

        deleted += 1

    return deleted, kept


@click.command(name="sync_datasources")
@with_appcontext
@click.option(
    "--path",
    "-p",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="YAML datasource file; its database list is the desired set.",
)
def sync_datasources(path: Path) -> None:
    """Import datasources, then delete databases absent from the config.

    Databases that still have datasets or reports are logged and left in place;
    the command does not cascade and does not fail because of them.
    """
    raw, desired = _load_config(path)
    _import_config(path, raw)
    deleted, kept = _prune_databases(desired)

    click.echo(
        f"Datasource sync complete: {deleted} database(s) deleted, {len(kept)} kept"
    )
