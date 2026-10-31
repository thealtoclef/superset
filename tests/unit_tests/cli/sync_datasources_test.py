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

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from click.testing import CliRunner
from pytest_mock import MockerFixture

from superset.cli import sync_datasources


def test_expand_env_replaces_only_declared_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DB_PASSWORD", "s3cret")

    raw = sync_datasources._expand_env(
        "password=${DB_PASSWORD}&literal=$HOME&unknown=${NOPE}"
        '&extra={"password":"$value"}'
    )

    assert raw == (
        'password=s3cret&literal=$HOME&unknown=${NOPE}&extra={"password":"$value"}'
    )


def test_load_config_expands_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DB_PASSWORD", "s3cret")
    path = tmp_path / "datasources.yaml"
    path.write_text(
        "databases:\n"
        "  - database_name: cake-x\n"
        "    sqlalchemy_uri: mysql://user:${DB_PASSWORD}@host/db\n",
        encoding="utf-8",
    )

    raw, desired = sync_datasources._load_config(path)

    assert "s3cret" in raw
    assert "${DB_PASSWORD}" not in raw
    assert desired == {"cake-x"}


def test_load_config_handles_yaml_special_characters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DB_PASSWORD", 'p#ss: "word"')
    path = tmp_path / "datasources.yaml"
    path.write_text(
        "databases:\n"
        "  - database_name: cake-x\n"
        "    sqlalchemy_uri: mysql://user:${DB_PASSWORD}@host/db\n",
        encoding="utf-8",
    )

    raw, _ = sync_datasources._load_config(path)

    parsed = yaml.safe_load(raw)
    assert parsed["databases"][0]["sqlalchemy_uri"] == (
        'mysql://user:p#ss: "word"@host/db'
    )


def test_load_config_requires_databases(tmp_path: Path) -> None:
    path = tmp_path / "datasources.yaml"
    path.write_text("other: []\n", encoding="utf-8")

    with pytest.raises(Exception, match="no 'databases' key"):
        sync_datasources._load_config(path)


def test_load_config_rejects_duplicate_database_names(tmp_path: Path) -> None:
    path = tmp_path / "datasources.yaml"
    path.write_text(
        "databases:\n  - database_name: cake-x\n  - database_name: cake-x\n",
        encoding="utf-8",
    )

    with pytest.raises(Exception, match="Duplicate"):
        sync_datasources._load_config(path)


def test_import_config_uses_v0_importer(mocker: MockerFixture) -> None:
    raw = "databases: []\n"
    command = mocker.patch(
        "superset.commands.dataset.importers.v0.ImportDatasetsCommand"
    )

    sync_datasources._import_config(Path("datasources.yaml"), raw)

    command.assert_called_once_with({"datasources.yaml": raw})
    command.return_value.run.assert_called_once_with()


def test_prune_deletes_empty_database_and_logs_dataset_ids(
    mocker: MockerFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    empty = SimpleNamespace(id=1, database_name="empty")
    busy = SimpleNamespace(id=2, database_name="busy")
    session = mocker.MagicMock()
    session.query.return_value.all.return_value = [empty, busy]
    mocker.patch.object(sync_datasources, "db", SimpleNamespace(session=session))
    mocker.patch.object(
        sync_datasources,
        "_dataset_ids",
        side_effect=lambda database_id: [10, 11] if database_id == 2 else [],
    )
    mocker.patch.object(
        sync_datasources.ReportScheduleDAO,
        "find_by_database_id",
        return_value=[],
    )
    delete = mocker.patch.object(sync_datasources, "DeleteDatabaseCommand")

    deleted, kept = sync_datasources._prune_databases({"cake-x"})

    assert (deleted, kept) == (1, ["busy"])
    delete.assert_called_once_with(1)
    delete.return_value.run.assert_called_once_with()
    error = capsys.readouterr().err
    assert "Cannot delete database busy" in error
    assert "dataset id(s) [10, 11]" in error


def test_prune_keeps_database_with_reports(
    mocker: MockerFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = SimpleNamespace(id=3, database_name="reported")
    session = mocker.MagicMock()
    session.query.return_value.all.return_value = [database]
    mocker.patch.object(sync_datasources, "db", SimpleNamespace(session=session))
    mocker.patch.object(sync_datasources, "_dataset_ids", return_value=[])
    mocker.patch.object(
        sync_datasources.ReportScheduleDAO,
        "find_by_database_id",
        return_value=[SimpleNamespace(id=7)],
    )
    delete = mocker.patch.object(sync_datasources, "DeleteDatabaseCommand")

    deleted, kept = sync_datasources._prune_databases(set())

    assert (deleted, kept) == (0, ["reported"])
    delete.assert_not_called()
    assert "report schedule id(s) [7]" in capsys.readouterr().err


def test_prune_continues_when_delete_fails(
    mocker: MockerFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = SimpleNamespace(id=4, database_name="broken")
    session = mocker.MagicMock()
    session.query.return_value.all.return_value = [database]
    mocker.patch.object(sync_datasources, "db", SimpleNamespace(session=session))
    mocker.patch.object(sync_datasources, "_dataset_ids", return_value=[])
    mocker.patch.object(
        sync_datasources.ReportScheduleDAO,
        "find_by_database_id",
        return_value=[],
    )
    delete = mocker.patch.object(sync_datasources, "DeleteDatabaseCommand")
    delete.return_value.run.side_effect = RuntimeError("fk")

    deleted, kept = sync_datasources._prune_databases(set())

    assert (deleted, kept) == (0, ["broken"])
    assert "failed to delete database broken" in capsys.readouterr().err


def test_sync_datasources_command_wires_import_and_prune(
    mocker: MockerFixture,
    app_context: None,
    tmp_path: Path,
) -> None:
    path = tmp_path / "datasources.yaml"
    path.write_text("databases: []\n", encoding="utf-8")
    mocker.patch.object(
        sync_datasources,
        "_load_config",
        return_value=("databases: []\n", set()),
    )
    import_config = mocker.patch.object(sync_datasources, "_import_config")
    prune = mocker.patch.object(
        sync_datasources,
        "_prune_databases",
        return_value=(2, ["busy"]),
    )

    result = CliRunner().invoke(
        sync_datasources.sync_datasources,
        ["--path", str(path)],
    )

    assert result.exit_code == 0, result.output
    import_config.assert_called_once_with(path, "databases: []\n")
    prune.assert_called_once_with(set())
    assert "2 database(s) deleted, 1 kept" in result.output
