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
from typing import Any

import pytest
from flask import current_app
from pytest_mock import MockerFixture

from superset.extensions import appbuilder
from superset.security.manager import SupersetSecurityManager


def _pvm(permission: str, view: str) -> Any:
    return SimpleNamespace(
        permission=SimpleNamespace(name=permission),
        view_menu=SimpleNamespace(name=view),
    )


@pytest.fixture
def banned_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(current_app.config, "BANNED_PERMISSIONS", ["can_grant"])
    monkeypatch.setitem(current_app.config, "BANNED_VIEWS", ["RowLevelSecurity"])
    monkeypatch.setitem(current_app.config, "BANNED_PVMS", [["can_read", "SecretView"]])


@pytest.fixture
def security_manager(app_context: None, banned_config: None) -> SupersetSecurityManager:
    return SupersetSecurityManager(appbuilder)


def test_set_role_filters_banned_permissions(
    security_manager: SupersetSecurityManager,
    mocker: MockerFixture,
) -> None:
    role = SimpleNamespace(name="Gamma", permissions=[])
    mocker.patch.object(security_manager, "add_role", return_value=role)
    allowed = _pvm("can_read", "Dashboard")
    denied = _pvm("can_grant", "Dashboard")

    security_manager.set_role("Gamma", lambda _pvm: True, [allowed, denied])

    assert role.permissions == [allowed]


def test_banned_view_and_pvm_are_denied(
    security_manager: SupersetSecurityManager,
) -> None:
    assert security_manager._is_banned_permission("can_read", "RowLevelSecurity")
    assert security_manager._is_banned_permission("can_read", "SecretView")
    assert not security_manager._is_banned_permission("can_read", "Dashboard")


def test_set_role_preserves_exempt_role(
    security_manager: SupersetSecurityManager,
    mocker: MockerFixture,
) -> None:
    role = SimpleNamespace(name="Admin", permissions=[])
    mocker.patch.object(security_manager, "add_role", return_value=role)
    denied = _pvm("can_grant", "Dashboard")

    security_manager.set_role("Admin", lambda _pvm: True, [denied])

    assert role.permissions == [denied]


def test_banned_pvm_blocks_permission_check(
    security_manager: SupersetSecurityManager,
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "flask_appbuilder.security.sqla.manager.SecurityManager._has_view_access",
        return_value=True,
    )
    gamma_user = SimpleNamespace(roles=[SimpleNamespace(name="Gamma")])
    admin_user = SimpleNamespace(roles=[SimpleNamespace(name="Admin")])

    assert not security_manager._has_view_access(gamma_user, "can_grant", "Dashboard")
    assert security_manager._has_view_access(gamma_user, "can_read", "Dashboard")
    assert security_manager._has_view_access(admin_user, "can_grant", "Dashboard")


def test_add_permission_role_refuses_banned_permission(
    security_manager: SupersetSecurityManager,
    mocker: MockerFixture,
) -> None:
    parent = mocker.patch(
        "flask_appbuilder.security.sqla.manager.SecurityManager.add_permission_role"
    )
    role = SimpleNamespace(name="Gamma")

    security_manager.add_permission_role(role, _pvm("can_grant", "Dashboard"))

    parent.assert_not_called()
