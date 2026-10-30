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
from click.testing import CliRunner
from pytest_mock import MockerFixture

from superset.cli import sync_access


def _pvm(permission: str, view: str) -> SimpleNamespace:
    return SimpleNamespace(
        permission=SimpleNamespace(name=permission),
        view_menu=SimpleNamespace(name=view),
    )


def test_load_config_rejects_non_mapping(tmp_path: Path) -> None:
    path = tmp_path / "access.yaml"
    path.write_text("- not-a-mapping\n", encoding="utf-8")

    with pytest.raises(Exception, match="mapping"):
        sync_access._load_config(path)


def test_load_config_rejects_role_first_format(tmp_path: Path) -> None:
    path = tmp_path / "access.yaml"
    path.write_text("roles: {}\n", encoding="utf-8")

    with pytest.raises(Exception, match="Role-first"):
        sync_access._load_config(path)


def test_desired_permissions_groups_by_database(
    mocker: MockerFixture,
) -> None:
    databases = {
        "database_a": SimpleNamespace(
            database_name="database_a",
            perm="[database_a].(id:1)",
        ),
        "database_b": SimpleNamespace(
            database_name="database_b",
            perm="[database_b].(id:2)",
        ),
    }
    mocker.patch.object(
        sync_access,
        "_resolve_database",
        side_effect=lambda name: databases[name],
    )
    mocker.patch.object(
        sync_access,
        "_resolve_pvm",
        side_effect=lambda permission, view, _label: _pvm(permission, view),
    )

    desired = sync_access._desired_permissions(
        {
            "databases": {
                "database_a": {
                    "datasets": ["role_a"],
                    "database": ["role_b"],
                },
                "database_b": {
                    "database": ["role_a"],
                },
            }
        }
    )

    assert desired == {
        "role_a": {
            ("database_dataset_access", "[database_a].(id:1)"): _pvm(
                "database_dataset_access", "[database_a].(id:1)"
            ),
            ("database_access", "[database_b].(id:2)"): _pvm(
                "database_access", "[database_b].(id:2)"
            ),
        },
        "role_b": {
            ("database_access", "[database_a].(id:1)"): _pvm(
                "database_access", "[database_a].(id:1)"
            ),
        },
    }


def test_load_config_rejects_top_level_datasets(tmp_path: Path) -> None:
    path = tmp_path / "access.yaml"
    path.write_text("datasets: []\n", encoding="utf-8")

    with pytest.raises(Exception, match="Top-level"):
        sync_access._load_config(path)


def test_sync_role_requires_existing_role(mocker: MockerFixture) -> None:
    manager = mocker.MagicMock()
    mocker.patch.object(sync_access, "security_manager", manager)
    manager.find_role.return_value = None

    with pytest.raises(Exception, match="Role not found"):
        sync_access._sync_role("team_new", {})

    manager.add_role.assert_not_called()


def test_sync_role_adds_and_prunes_managed_permissions(
    mocker: MockerFixture,
) -> None:
    role = SimpleNamespace(
        name="team_finance",
        permissions=[
            _pvm("database_access", "[old].(id:1)"),
            _pvm("can_read", "Dashboard"),
        ],
    )
    new_pvm = _pvm("database_dataset_access", "[db].(id:2)")
    manager = mocker.MagicMock()
    mocker.patch.object(sync_access, "security_manager", manager)
    manager.find_role.return_value = role
    manager.add_permission_role.side_effect = lambda _role, pvm: (
        role.permissions.append(pvm)
    )
    manager.del_permission_role.side_effect = lambda _role, pvm: (
        role.permissions.remove(pvm)
    )

    added, removed = sync_access._sync_role(
        "team_finance",
        {("database_dataset_access", "[db].(id:2)"): new_pvm},
    )

    assert (added, removed) == (1, 1)
    assert new_pvm in role.permissions
    assert _pvm("can_read", "Dashboard") in role.permissions
    assert _pvm("database_access", "[old].(id:1)") not in role.permissions


def test_sync_access_command_wires_roles(
    mocker: MockerFixture,
    app_context: None,
    tmp_path: Path,
) -> None:
    path = tmp_path / "access.yaml"
    path.write_text("databases: []\n", encoding="utf-8")
    mocker.patch(
        "superset.cli.sync_access._load_config",
        return_value={
            "databases": {
                "database_a": {
                    "datasets": ["team_finance"],
                }
            }
        },
    )
    pvm = _pvm("database_dataset_access", "[database_a].(id:1)")
    mocker.patch(
        "superset.cli.sync_access._desired_permissions",
        return_value={
            "team_finance": {("database_dataset_access", "[database_a].(id:1)"): pvm}
        },
    )
    manager = mocker.MagicMock()
    mocker.patch.object(sync_access, "security_manager", manager)
    manager.get_all_roles.return_value = [
        SimpleNamespace(name="team_finance"),
        SimpleNamespace(name="team_orphan"),
    ]
    manager.auth_role_admin = "Admin"
    sync_role = mocker.patch(
        "superset.cli.sync_access._sync_role",
        return_value=(1, 0),
    )

    result = CliRunner().invoke(
        sync_access.sync_access,
        ["--path", str(path)],
    )

    assert result.exit_code == 0, result.output
    assert sync_role.call_args_list == [
        mocker.call(
            "team_finance",
            {("database_dataset_access", "[database_a].(id:1)"): pvm},
        ),
        mocker.call("team_orphan", {}),
    ]
    assert "team_finance: 1 added, 0 removed" in result.output
    manager.del_user_role.assert_not_called()
    manager.delete_role.assert_not_called()


def test_sync_access_skips_admin_role(
    mocker: MockerFixture,
    app_context: None,
    tmp_path: Path,
) -> None:
    path = tmp_path / "access.yaml"
    path.write_text("databases: []\n", encoding="utf-8")
    mocker.patch.object(sync_access, "_load_config", return_value={"databases": {}})
    mocker.patch.object(sync_access, "_desired_permissions", return_value={})
    manager = mocker.MagicMock()
    mocker.patch.object(sync_access, "security_manager", manager)
    manager.get_all_roles.return_value = [
        SimpleNamespace(name="Admin"),
        SimpleNamespace(name="team_readonly"),
    ]
    manager.auth_role_admin = "Admin"
    sync_role = mocker.patch.object(
        sync_access,
        "_sync_role",
        return_value=(0, 0),
    )

    result = CliRunner().invoke(sync_access.sync_access, ["--path", str(path)])

    assert result.exit_code == 0, result.output
    sync_role.assert_called_once_with("team_readonly", {})


def test_sync_access_rejects_role_missing_from_database(
    mocker: MockerFixture,
    app_context: None,
    tmp_path: Path,
) -> None:
    path = tmp_path / "access.yaml"
    path.write_text("databases: []\n", encoding="utf-8")
    mocker.patch.object(sync_access, "_load_config", return_value={"databases": {}})
    mocker.patch.object(
        sync_access,
        "_desired_permissions",
        return_value={"team_missing": {}},
    )
    manager = mocker.MagicMock()
    mocker.patch.object(sync_access, "security_manager", manager)
    manager.get_all_roles.return_value = [SimpleNamespace(name="team_existing")]
    manager.auth_role_admin = "Admin"

    result = CliRunner().invoke(sync_access.sync_access, ["--path", str(path)])

    assert result.exit_code == 1
    assert "Role not found: team_missing" in result.output
