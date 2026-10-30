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

from types import SimpleNamespace

from pytest_mock import MockerFixture

from superset import security_manager
from superset.security.manager import SupersetSecurityManager


def test_database_dataset_access_grants_dataset_schema(
    app_context: None,
    mocker: MockerFixture,
) -> None:
    datasource = SimpleNamespace(
        database=SimpleNamespace(perm="[db].(id:1)"),
        catalog=None,
        schema_perm="[db].[public]",
    )
    mocker.patch.object(
        security_manager, "can_access_all_datasources", return_value=False
    )
    mocker.patch.object(security_manager, "can_access_database", return_value=False)
    mocker.patch.object(
        security_manager,
        "can_access",
        side_effect=lambda permission, view: (
            (
                permission,
                view,
            )
            == ("database_dataset_access", "[db].(id:1)")
        ),
    )

    assert security_manager.can_access_schema(datasource) is True


def test_database_dataset_access_does_not_grant_database_access(
    app_context: None,
    mocker: MockerFixture,
) -> None:
    database = SimpleNamespace(perm="[db].(id:1)")
    mocker.patch.object(
        security_manager, "can_access_all_datasources", return_value=False
    )
    mocker.patch.object(
        security_manager, "can_access_all_databases", return_value=False
    )
    mocker.patch.object(
        security_manager,
        "can_access",
        side_effect=lambda permission, view: (
            (
                permission,
                view,
            )
            == ("database_dataset_access", "[db].(id:1)")
        ),
    )

    assert security_manager.can_access_database(database) is False


def test_create_missing_perms_creates_database_dataset_access(
    app_context: None,
    mocker: MockerFixture,
) -> None:
    database = SimpleNamespace(perm="[db].(id:1)")
    manager = mocker.MagicMock()
    manager._get_all_pvms.return_value = []
    manager.session.query.return_value.all.return_value = [database]
    mocker.patch(
        "superset.connectors.sqla.models.SqlaTable.get_all_datasources",
        return_value=[],
    )

    SupersetSecurityManager.create_missing_perms(manager)

    manager.add_permission_view_menu.assert_any_call(
        "database_dataset_access", "[db].(id:1)"
    )
