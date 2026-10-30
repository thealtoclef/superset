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

import pytest
from flask import current_app
from pytest_mock import MockerFixture

from superset.extensions import appbuilder
from superset.security.manager import SupersetSecurityManager


@pytest.fixture
def security_manager(app_context: None) -> SupersetSecurityManager:
    return SupersetSecurityManager(appbuilder)


def test_static_role_mapping_adds_roles_case_insensitively(
    security_manager: SupersetSecurityManager,
    monkeypatch: pytest.MonkeyPatch,
    mocker: MockerFixture,
) -> None:
    gamma = SimpleNamespace(name="Gamma")
    team = SimpleNamespace(name="doris_platform")
    mocker.patch(
        "flask_appbuilder.security.sqla.manager.SecurityManager._oauth_calculate_user_roles",
        return_value=[gamma],
    )
    mocker.patch.object(
        security_manager,
        "find_role",
        side_effect=lambda name: team if name == "doris_platform" else None,
    )
    monkeypatch.setitem(
        current_app.config,
        "AUTH_STATIC_ROLE_MAPPING",
        {"doris_platform": ["Alice@Cake.vn"], "missing": ["alice@cake.vn"]},
    )

    roles = security_manager._oauth_calculate_user_roles({"email": "alice@cake.vn"})

    assert roles == [gamma, team]


def test_static_roles_for_user_include_registration_role(
    security_manager: SupersetSecurityManager,
    monkeypatch: pytest.MonkeyPatch,
    mocker: MockerFixture,
) -> None:
    gamma = SimpleNamespace(name="Gamma")
    team = SimpleNamespace(name="doris_platform")
    monkeypatch.setitem(current_app.config, "AUTH_USER_REGISTRATION_ROLE", "Gamma")
    monkeypatch.setitem(
        current_app.config,
        "AUTH_STATIC_ROLE_MAPPING",
        {"doris_platform": ["alice@cake.vn"]},
    )
    mocker.patch.object(
        security_manager,
        "find_role",
        side_effect=lambda name: {
            "Gamma": gamma,
            "doris_platform": team,
        }.get(name),
    )

    roles = security_manager._static_roles_for_user(
        SimpleNamespace(email="alice@cake.vn")
    )

    assert roles == [gamma, team]


def test_static_role_mapping_without_email_keeps_idp_roles(
    security_manager: SupersetSecurityManager,
    monkeypatch: pytest.MonkeyPatch,
    mocker: MockerFixture,
) -> None:
    gamma = SimpleNamespace(name="Gamma")
    mocker.patch(
        "flask_appbuilder.security.sqla.manager.SecurityManager._oauth_calculate_user_roles",
        return_value=[gamma],
    )
    monkeypatch.setitem(
        current_app.config,
        "AUTH_STATIC_ROLE_MAPPING",
        {"doris_platform": ["alice@cake.vn"]},
    )

    assert security_manager._oauth_calculate_user_roles({}) == [gamma]
