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
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator, TYPE_CHECKING

from superset.exceptions import (
    DatasetExecutionUserInvalidError,
    DatasetExecutionUserTokenMissingError,
)
from superset.extensions import feature_flag_manager, security_manager
from superset.utils.core import get_user
from superset.utils.database import find_user_for_impersonation

if TYPE_CHECKING:
    from flask_appbuilder.security.sqla.models import User

    from superset.models.core import Database

FEATURE_FLAG = "DATASET_EXECUTION_USER"

_execution_user: ContextVar[User | None] = ContextVar("execution_user", default=None)


def get_execution_user() -> User | None:
    return _execution_user.get()


@contextmanager
def execution_identity(user: User | None) -> Iterator[None]:
    token = _execution_user.set(user)
    try:
        yield
    finally:
        _execution_user.reset(token)


def supports_execution_user(database: Database) -> bool:
    return bool(database.impersonate_user and database.get_oauth2_config() is not None)


def can_assign_execution_user(username: str | None) -> bool:
    user = get_user()
    if user is None:
        return False
    return username is None or username == user.username or security_manager.is_admin()


def get_active_user(username: str) -> User:
    user = find_user_for_impersonation(username)
    if user is None or not user.active:
        raise DatasetExecutionUserInvalidError(username)
    return user


def resolve_execution_user(dataset: Any) -> User | None:
    if not feature_flag_manager.is_feature_enabled(FEATURE_FLAG):
        return None

    getter = getattr(dataset, "get_execution_user_username", None)
    if getter is None:
        return None

    username = getter()
    if not username:
        return None

    database = dataset.database
    if database is None or not supports_execution_user(database):
        return None

    return get_active_user(username)


def raise_for_impersonated_execution(database: Database) -> None:
    if user := _execution_user.get():
        raise DatasetExecutionUserTokenMissingError(user.username, database.name)
