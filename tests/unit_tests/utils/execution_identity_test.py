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

import pandas as pd
import pytest
from pytest_mock import MockerFixture

from superset.connectors.sqla.models import SqlaTable
from superset.exceptions import (
    DatasetExecutionUserInvalidError,
    DatasetExecutionUserTokenMissingError,
)
from superset.utils.execution_identity import (
    execution_identity,
    get_active_user,
    raise_for_impersonated_execution,
    resolve_execution_user,
    supports_execution_user,
)
from tests.unit_tests.conftest import with_feature_flags


def _dataset(
    username: str | None = "alice",
    *,
    impersonate: bool = True,
    oauth2: bool = True,
) -> SimpleNamespace:
    database = SimpleNamespace(
        impersonate_user=impersonate,
        get_oauth2_config=lambda: {} if oauth2 else None,
    )
    dataset = SimpleNamespace(database=database)
    dataset.get_execution_user_username = lambda: username
    return dataset


def test_model_helpers_preserve_extra() -> None:
    table = SqlaTable(extra='{"warning_markdown": "careful"}')

    table.set_execution_user_username("alice")
    assert table.get_execution_user_username() == "alice"
    assert table.extra_dict["warning_markdown"] == "careful"

    table.set_execution_user_username(None)
    assert table.get_execution_user_username() is None
    assert table.extra_dict["warning_markdown"] == "careful"


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_extra_cache_keys_partition_by_execution_user(
    mocker: MockerFixture, app_context
) -> None:
    table = SqlaTable(extra='{"execution_user": "alice"}')
    mocker.patch(
        "superset.utils.execution_identity.resolve_execution_user",
        return_value=SimpleNamespace(id=42),
    )

    assert "execution_user:42" in table.get_extra_cache_keys({})


@with_feature_flags(DATASET_EXECUTION_USER=False)
def test_extra_cache_keys_ignore_identity_when_flag_is_off(app_context) -> None:
    table = SqlaTable(extra='{"execution_user": "alice"}')

    assert not any(
        key.startswith("execution_user:") for key in table.get_extra_cache_keys({})
    )


@with_feature_flags(DATASET_EXECUTION_USER=False)
def test_resolve_is_inert_when_flag_is_off() -> None:
    assert resolve_execution_user(_dataset()) is None


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_resolve_is_inert_without_setting() -> None:
    assert resolve_execution_user(_dataset(username=None)) is None


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_resolve_requires_impersonation(mocker: MockerFixture) -> None:
    mocker.patch("superset.utils.execution_identity.find_user_for_impersonation")
    assert resolve_execution_user(_dataset(impersonate=False)) is None


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_resolve_requires_oauth2_config(mocker: MockerFixture) -> None:
    mocker.patch("superset.utils.execution_identity.find_user_for_impersonation")
    assert resolve_execution_user(_dataset(oauth2=False)) is None


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_resolve_returns_active_user(mocker: MockerFixture) -> None:
    user = SimpleNamespace(id=2, username="alice", active=True)
    mocker.patch(
        "superset.utils.execution_identity.find_user_for_impersonation",
        return_value=user,
    )

    assert resolve_execution_user(_dataset()) is user


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_resolve_rejects_inactive_user(mocker: MockerFixture) -> None:
    mocker.patch(
        "superset.utils.execution_identity.find_user_for_impersonation",
        return_value=SimpleNamespace(id=2, username="alice", active=False),
    )

    with pytest.raises(DatasetExecutionUserInvalidError):
        resolve_execution_user(_dataset())


def test_get_active_user_raises_for_missing_user(mocker: MockerFixture) -> None:
    mocker.patch(
        "superset.utils.execution_identity.find_user_for_impersonation",
        return_value=None,
    )

    with pytest.raises(DatasetExecutionUserInvalidError):
        get_active_user("nobody")


def test_supports_execution_user() -> None:
    assert supports_execution_user(_dataset().database)
    assert not supports_execution_user(_dataset(impersonate=False).database)
    assert not supports_execution_user(_dataset(oauth2=False).database)


def test_dance_is_suppressed_for_execution_user() -> None:
    database = SimpleNamespace(name="doris")
    with execution_identity(SimpleNamespace(id=2, username="alice")):
        with pytest.raises(DatasetExecutionUserTokenMissingError):
            raise_for_impersonated_execution(database)


@with_feature_flags(DATASET_EXECUTION_USER=True)
def test_dataset_query_uses_execution_user(mocker: MockerFixture, app_context) -> None:
    user = SimpleNamespace(id=2, username="alice", active=True)
    mocker.patch(
        "superset.utils.execution_identity.find_user_for_impersonation",
        return_value=user,
    )
    table = SqlaTable(extra='{"execution_user": "alice"}')
    table.database = mocker.MagicMock()
    table.database.impersonate_user = True
    table.database.get_oauth2_config.return_value = {"id": "client"}
    table.get_query_str_extended = mocker.MagicMock(
        return_value=SimpleNamespace(
            sql="SELECT 1",
            labels_expected=[],
            applied_template_filters=[],
            applied_filter_columns=[],
            rejected_filter_columns=[],
            sql_shifted_temporal_labels=set(),
        )
    )
    table._raise_for_disallowed_sql = mocker.MagicMock()
    table.database.get_df.return_value = pd.DataFrame()

    table.query({})

    assert table.database.get_df.call_args.kwargs["execution_user"] is user
