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
import pytest
from marshmallow import ValidationError
from pytest_mock import MockerFixture

from superset.commands.dataset.create import CreateDatasetCommand
from superset.commands.dataset.exceptions import (
    DatasetForbiddenError,
)
from superset.commands.dataset.importers.v1.utils import sanitize_execution_user
from superset.commands.dataset.update import UpdateDatasetCommand
from tests.unit_tests.conftest import with_feature_flags


def _database(mocker: MockerFixture) -> object:
    database = mocker.MagicMock()
    database.impersonate_user = True
    database.get_oauth2_config.return_value = {"id": "client"}
    return database


def _model(mocker: MockerFixture, stored: str | None = None) -> object:
    model = mocker.MagicMock()
    model.is_managed_externally = False
    model.database = _database(mocker)
    model.get_execution_user_username.return_value = stored
    return model


def _user(name: str) -> object:
    user = type("User", (), {})()
    user.username = name
    return user


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_update_allows_non_admin_self(mocker: MockerFixture) -> None:
    command = UpdateDatasetCommand(1, {"execution_user": "alice"})
    command._model = _model(mocker)
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("alice")
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.is_admin",
        return_value=False,
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.find_user",
        return_value=mocker.MagicMock(active=True),
    )

    command._validate_execution_user([])
    assert command._execution_user == "alice"


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_update_persists_non_admin_self(mocker: MockerFixture, app_context) -> None:
    command = UpdateDatasetCommand(1, {"execution_user": "alice"})
    model = _model(mocker)
    command._model = model
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("alice")
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.is_admin",
        return_value=False,
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.find_user",
        return_value=mocker.MagicMock(active=True),
    )
    command._validate_execution_user([])
    mocker.patch.object(command, "validate")
    mocker.patch(
        "superset.commands.dataset.update.DatasetDAO.update", return_value=model
    )

    command.run()

    model.set_execution_user_username.assert_called_once_with("alice")


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_update_rejects_non_admin_other_user(mocker: MockerFixture) -> None:
    command = UpdateDatasetCommand(1, {"execution_user": "bob"})
    command._model = _model(mocker)
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("alice")
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.is_admin",
        return_value=False,
    )

    with pytest.raises(DatasetForbiddenError):
        command._validate_execution_user([])


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_update_allows_non_admin_clear(mocker: MockerFixture) -> None:
    command = UpdateDatasetCommand(1, {"execution_user": None})
    command._model = _model(mocker, stored="alice")
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("bob")
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.is_admin",
        return_value=False,
    )

    command._validate_execution_user([])
    assert command._execution_user is None


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_update_allows_non_admin_noop(mocker: MockerFixture) -> None:
    command = UpdateDatasetCommand(1, {"execution_user": "alice"})
    command._model = _model(mocker, stored="alice")
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("bob")
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.is_admin",
        return_value=False,
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.find_user",
        return_value=mocker.MagicMock(active=True),
    )

    command._validate_execution_user([])
    assert command._execution_user == "alice"


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_update_ignores_unchanged_invalid_stored_user(
    mocker: MockerFixture,
) -> None:
    command = UpdateDatasetCommand(1, {"execution_user": "ghost"})
    command._model = _model(mocker, stored="ghost")
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("bob")
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.is_admin",
        return_value=False,
    )
    find_user = mocker.patch(
        "superset.commands.dataset.update.security_manager.find_user"
    )

    exceptions: list[ValidationError] = []
    command._validate_execution_user(exceptions)

    assert not exceptions
    find_user.assert_not_called()


@with_feature_flags(DATASET_EXECUTION_USER=False)
def test_update_flag_off_allows_unchanged_value(mocker: MockerFixture) -> None:
    command = UpdateDatasetCommand(1, {"execution_user": None})
    command._model = _model(mocker, stored=None)

    command._validate_execution_user([])

    assert command._execution_user is None


@with_feature_flags(DATASET_EXECUTION_USER=False)
def test_update_flag_off_rejects_changed_value(mocker: MockerFixture) -> None:
    command = UpdateDatasetCommand(1, {"execution_user": "alice"})
    command._model = _model(mocker, stored=None)

    exceptions: list[ValidationError] = []
    command._validate_execution_user(exceptions)

    assert exceptions[0].field_name == "execution_user"


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_update_rejects_foreign_source_change(mocker: MockerFixture) -> None:
    command = UpdateDatasetCommand(1, {"sql": "select 2"})
    model = _model(mocker, stored="alice")
    model.sql = "select 1"
    command._model = model
    command._execution_user = "alice"
    mocker.patch.object(command, "_get_new_database_connection", return_value=None)
    mocker.patch.object(
        command, "_resolve_catalog_schema_table", return_value=(None, None, None)
    )
    mocker.patch(
        "superset.commands.dataset.update.DatasetDAO.validate_update_uniqueness",
        return_value=True,
    )
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("bob")
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.is_admin",
        return_value=False,
    )

    with pytest.raises(DatasetForbiddenError):
        command._validate_dataset_source([])


@with_feature_flags(DATASET_EXECUTION_USER=False)
def test_update_ignores_owner_source_restriction_when_disabled(
    mocker: MockerFixture,
) -> None:
    command = UpdateDatasetCommand(1, {"sql": "select 2"})
    model = _model(mocker, stored="alice")
    model.sql = "select 1"
    model.database.impersonate_user = False
    model.database.get_oauth2_config.return_value = None
    command._model = model
    command._execution_user = "alice"
    mocker.patch.object(command, "_get_new_database_connection", return_value=None)
    mocker.patch.object(
        command, "_resolve_catalog_schema_table", return_value=(None, None, None)
    )
    mocker.patch(
        "superset.commands.dataset.update.DatasetDAO.validate_update_uniqueness",
        return_value=True,
    )
    mocker.patch.object(command, "_validate_sql_access")

    command._validate_dataset_source([])


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_update_rejects_foreign_template_params_change(
    mocker: MockerFixture,
) -> None:
    command = UpdateDatasetCommand(1, {"template_params": '{"source_table": "other"}'})
    model = _model(mocker, stored="alice")
    model.template_params = '{"source_table": "own"}'
    command._model = model
    command._execution_user = "alice"
    mocker.patch.object(command, "_get_new_database_connection", return_value=None)
    mocker.patch.object(
        command, "_resolve_catalog_schema_table", return_value=(None, None, None)
    )
    mocker.patch(
        "superset.commands.dataset.update.DatasetDAO.validate_update_uniqueness",
        return_value=True,
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.is_admin",
        return_value=False,
    )
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("bob")
    )
    mocker.patch.object(command, "_validate_sql_access")

    with pytest.raises(DatasetForbiddenError):
        command._validate_dataset_source([])


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_update_allows_own_source_change(mocker: MockerFixture) -> None:
    command = UpdateDatasetCommand(1, {"sql": "select 2"})
    model = _model(mocker, stored="alice")
    model.sql = "select 1"
    command._model = model
    command._execution_user = "alice"
    mocker.patch.object(command, "_get_new_database_connection", return_value=None)
    mocker.patch.object(
        command, "_resolve_catalog_schema_table", return_value=(None, None, None)
    )
    mocker.patch(
        "superset.commands.dataset.update.DatasetDAO.validate_update_uniqueness",
        return_value=True,
    )
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("alice")
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.is_admin",
        return_value=False,
    )
    mocker.patch.object(command, "_validate_sql_access")

    command._validate_dataset_source([])


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_update_rejects_extra_tampering(mocker: MockerFixture) -> None:
    command = UpdateDatasetCommand(1, {"extra": '{"execution_user": "bob"}'})
    command._model = _model(mocker, stored="alice")
    mocker.patch(
        "superset.commands.dataset.update.security_manager.is_admin",
        return_value=False,
    )
    mocker.patch("superset.commands.dataset.update.get_user", return_value=object())

    with pytest.raises(DatasetForbiddenError):
        command._validate_execution_user([])


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_update_validates_user_and_persists(mocker: MockerFixture, app_context) -> None:
    command = UpdateDatasetCommand(1, {"execution_user": "alice"})
    model = _model(mocker)
    command._model = model
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("admin")
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.is_admin",
        return_value=True,
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.find_user",
        return_value=mocker.MagicMock(active=True),
    )

    exceptions: list[ValidationError] = []
    command._validate_execution_user(exceptions)
    assert not exceptions
    assert command._execution_user == "alice"

    mocker.patch.object(command, "validate")
    mocker.patch(
        "superset.commands.dataset.update.DatasetDAO.update", return_value=model
    )

    command.run()

    model.set_execution_user_username.assert_called_once_with("alice")


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_update_rejects_unknown_user(mocker: MockerFixture) -> None:
    command = UpdateDatasetCommand(1, {"execution_user": "ghost"})
    command._model = _model(mocker)
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("admin")
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.is_admin",
        return_value=True,
    )
    mocker.patch(
        "superset.commands.dataset.update.security_manager.find_user",
        return_value=None,
    )

    exceptions: list[ValidationError] = []
    command._validate_execution_user(exceptions)

    assert exceptions[0].field_name == "execution_user"


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_create_allows_non_admin_self(mocker: MockerFixture) -> None:
    command = CreateDatasetCommand({})
    command._execution_user = "alice"
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("alice")
    )
    mocker.patch(
        "superset.commands.dataset.create.security_manager.is_admin",
        return_value=False,
    )
    mocker.patch(
        "superset.commands.dataset.create.security_manager.find_user",
        return_value=mocker.MagicMock(active=True),
    )

    command._validate_execution_user(_database(mocker), [])


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_create_rejects_non_admin_other_user(mocker: MockerFixture) -> None:
    command = CreateDatasetCommand({})
    command._execution_user = "bob"
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("alice")
    )
    mocker.patch(
        "superset.commands.dataset.create.security_manager.is_admin",
        return_value=False,
    )

    with pytest.raises(DatasetForbiddenError):
        command._validate_execution_user(_database(mocker), [])


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_create_requires_oauth2_database(mocker: MockerFixture) -> None:
    command = CreateDatasetCommand({})
    command._execution_user = "alice"
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("admin")
    )
    mocker.patch(
        "superset.commands.dataset.create.security_manager.is_admin",
        return_value=True,
    )
    mocker.patch(
        "superset.commands.dataset.create.security_manager.find_user",
        return_value=mocker.MagicMock(active=True),
    )
    database = _database(mocker)
    database.impersonate_user = False

    exceptions: list[ValidationError] = []
    command._validate_execution_user(database, exceptions)

    assert exceptions[0].field_name == "execution_user"


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_import_drops_other_execution_user_for_non_admin(
    mocker: MockerFixture,
) -> None:
    config = {"extra": {"execution_user": "alice"}, "database_id": 1}
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("bob")
    )
    mocker.patch(
        "superset.commands.dataset.importers.v1.utils.security_manager.is_admin",
        return_value=False,
    )

    sanitize_execution_user(config, ignore_permissions=False)

    assert "execution_user" not in config["extra"]


def test_import_keeps_self_execution_user_for_non_admin(
    mocker: MockerFixture,
) -> None:
    config = {"extra": {"execution_user": "alice"}, "database_id": 1}
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("alice")
    )
    mocker.patch(
        "superset.commands.dataset.importers.v1.utils.security_manager.is_admin",
        return_value=False,
    )
    db = mocker.MagicMock()
    db.session.get.return_value = _database(mocker)
    mocker.patch(
        "superset.commands.dataset.importers.v1.utils.db",
        db,
    )
    mocker.patch(
        "superset.commands.dataset.importers.v1.utils.get_active_user",
    )

    sanitize_execution_user(config, ignore_permissions=False)

    assert config["extra"]["execution_user"] == "alice"


def test_import_keeps_valid_execution_user(mocker: MockerFixture) -> None:
    config = {"extra": {"execution_user": "alice"}, "database_id": 1}
    db = mocker.MagicMock()
    db.session.get.return_value = _database(mocker)
    mocker.patch(
        "superset.commands.dataset.importers.v1.utils.db",
        db,
    )
    mocker.patch(
        "superset.commands.dataset.importers.v1.utils.get_active_user",
    )

    sanitize_execution_user(config, ignore_permissions=True)

    assert config["extra"]["execution_user"] == "alice"


def test_import_drops_execution_user_from_json_string(mocker: MockerFixture) -> None:
    config = {"extra": '{"execution_user": "alice"}', "database_id": 1}
    mocker.patch(
        "superset.utils.execution_identity.get_user", return_value=_user("bob")
    )
    mocker.patch(
        "superset.commands.dataset.importers.v1.utils.security_manager.is_admin",
        return_value=False,
    )

    sanitize_execution_user(config, ignore_permissions=False)

    assert "execution_user" not in config["extra"]
