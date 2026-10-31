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

from superset.cli import sync_roles


def test_load_config_accepts_role_list_and_protected_roles(tmp_path: Path) -> None:
    path = tmp_path / "roles.yaml"
    path.write_text(
        "roles:\n  - team_finance\n  - team_platform\n"
        "protected_roles:\n  - manual_role\n",
        encoding="utf-8",
    )

    roles, protected = sync_roles._load_config(path)

    assert roles == {"team_finance", "team_platform"}
    assert protected == {"manual_role"}


def test_load_config_accepts_role_mapping(tmp_path: Path) -> None:
    path = tmp_path / "roles.yaml"
    path.write_text("roles:\n  team_finance: {}\n", encoding="utf-8")

    assert sync_roles._load_config(path) == ({"team_finance"}, set())


def test_load_config_rejects_duplicate_roles(tmp_path: Path) -> None:
    path = tmp_path / "roles.yaml"
    path.write_text("roles:\n  - team_finance\n  - team_finance\n", encoding="utf-8")

    with pytest.raises(Exception, match="Duplicate role name"):
        sync_roles._load_config(path)


def test_load_config_rejects_unknown_keys(tmp_path: Path) -> None:
    path = tmp_path / "roles.yaml"
    path.write_text("rolez: []\n", encoding="utf-8")

    with pytest.raises(Exception, match="Unknown role config key"):
        sync_roles._load_config(path)


def test_config_referenced_roles(
    mocker: MockerFixture,
    app_context: None,
) -> None:
    mocker.patch.object(
        sync_roles,
        "security_manager",
        SimpleNamespace(
            auth_role_admin="Admin",
            auth_role_public="Public",
            auth_user_registration_role="Gamma",
        ),
    )
    mocker.patch.dict(
        sync_roles.current_app.config,
        {
            "PUBLIC_ROLE_LIKE": "Gamma",
            "AUTH_STATIC_ROLE_MAPPING": {"doris_platform": ["alice@example.com"]},
            "AUTH_ROLES_MAPPING": {"idp_group": ["team_analytics"]},
        },
    )

    assert sync_roles._config_referenced_roles() == {
        "Admin",
        "Public",
        "Gamma",
        "doris_platform",
        "team_analytics",
    }


def test_sync_roles_creates_and_prunes(mocker: MockerFixture) -> None:
    roles = [
        SimpleNamespace(name="Admin"),
        SimpleNamespace(name="team_old"),
        SimpleNamespace(name="manual_role"),
    ]
    manager = mocker.MagicMock()
    manager.get_all_roles.side_effect = lambda: list(roles)
    mocker.patch.object(sync_roles, "security_manager", manager)
    create = mocker.patch.object(
        sync_roles.RoleDAO,
        "create",
        side_effect=lambda attributes: roles.append(
            SimpleNamespace(name=attributes["name"])
        ),
    )
    delete = mocker.patch.object(
        sync_roles.RoleDAO,
        "delete",
        side_effect=lambda items: [roles.remove(item) for item in items],
    )
    session = mocker.MagicMock()
    mocker.patch.object(sync_roles, "db", SimpleNamespace(session=session))

    created, deleted = sync_roles._sync_roles(
        {"Admin", "team_new"},
        {"Admin", "team_new", "manual_role"},
    )

    assert (created, deleted) == (1, 1)
    create.assert_called_once_with(attributes={"name": "team_new"})
    deleted_roles = delete.call_args.args[0]
    assert [role.name for role in deleted_roles] == ["team_old"]
    assert [role.name for role in roles] == ["Admin", "manual_role", "team_new"]
    session.commit.assert_called_once_with()


def test_sync_roles_does_not_create_missing_builtin(mocker: MockerFixture) -> None:
    manager = mocker.MagicMock()
    manager.get_all_roles.return_value = []
    mocker.patch.object(sync_roles, "security_manager", manager)
    create = mocker.patch.object(sync_roles.RoleDAO, "create")
    mocker.patch.object(sync_roles.RoleDAO, "delete")
    mocker.patch.object(
        sync_roles,
        "db",
        SimpleNamespace(session=mocker.MagicMock()),
    )

    assert sync_roles._sync_roles({"Admin"}, {"Admin"}) == (0, 0)
    create.assert_not_called()


def test_sync_roles_command_wires_desired_and_protected(
    mocker: MockerFixture,
    app_context: None,
    tmp_path: Path,
) -> None:
    path = tmp_path / "roles.yaml"
    path.write_text("roles: []\n", encoding="utf-8")
    mocker.patch.object(
        sync_roles,
        "_load_config",
        return_value=({"team_finance"}, {"manual_role"}),
    )
    mocker.patch.object(
        sync_roles,
        "_config_referenced_roles",
        return_value={"static_role"},
    )
    sync = mocker.patch.object(sync_roles, "_sync_roles", return_value=(1, 2))

    result = CliRunner().invoke(sync_roles.sync_roles, ["--path", str(path)])

    assert result.exit_code == 0, result.output
    desired = {"team_finance", "static_role"} | sync_roles.BUILTIN_ROLES
    sync.assert_called_once_with(desired, desired | {"manual_role"})
    assert "1 created, 2 deleted" in result.output
