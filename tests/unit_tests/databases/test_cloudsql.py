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
from typing import Any

import pytest
from pytest_mock import MockerFixture
from sqlalchemy.engine.url import make_url

from superset.databases import cloudsql


class FakeConnector:
    instances: list["FakeConnector"] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.instances.append(self)

    def connect(
        self, instance: str, driver: str, **kwargs: Any
    ) -> tuple[str, str, dict[str, Any]]:
        self.calls.append((instance, driver, kwargs))
        return instance, driver, kwargs


@pytest.fixture(autouse=True)
def fake_connector(mocker: MockerFixture) -> type[FakeConnector]:
    FakeConnector.instances = []
    mocker.patch.object(cloudsql, "_CONNECTORS", {})
    mocker.patch.object(cloudsql, "_connector_class", return_value=FakeConnector)
    return FakeConnector


def test_configure_postgres_iam() -> None:
    clean_url, params = cloudsql.configure_cloudsql(
        "postgresql+pg8000://sa@/db?"
        "cloudsql_instance=proj:reg:inst&"
        "cloudsql_ip_type=PRIVATE&"
        "cloudsql_enable_iam_auth=true"
    )

    assert clean_url.query == {}
    assert clean_url.username == "sa"
    assert clean_url.database == "db"
    assert params["pool_pre_ping"] is True
    assert params["pool_recycle"] == 1800

    creator = params["creator"]
    assert "iam=True" in repr(creator)
    assert creator() == ("proj:reg:inst", "pg8000", {"user": "sa", "db": "db"})
    assert FakeConnector.instances[0].kwargs == {
        "ip_type": "PRIVATE",
        "enable_iam_auth": True,
        "timeout": 30,
    }


def test_configure_mysql_with_password() -> None:
    _, params = cloudsql.configure_cloudsql(
        "mysql+pymysql://user:secret@/db?"
        "cloudsql_instance=proj:reg:inst&"
        "cloudsql_ip_type=PUBLIC"
    )

    creator = params["creator"]
    assert creator() == (
        "proj:reg:inst",
        "pymysql",
        {"client_flag": 2, "user": "user", "db": "db", "password": "secret"},
    )
    assert FakeConnector.instances[0].kwargs["enable_iam_auth"] is False


def test_connector_is_cached_per_instance() -> None:
    first_url, first_params = cloudsql.configure_cloudsql(
        "mysql+pymysql://user:secret@/db?cloudsql_instance=proj:reg:inst"
    )
    second_url, second_params = cloudsql.configure_cloudsql(
        "mysql+pymysql://user:secret@/db?cloudsql_instance=proj:reg:inst"
    )

    assert first_url == second_url
    first_params["creator"]()
    second_params["creator"]()

    assert len(FakeConnector.instances) == 1
    assert len(FakeConnector.instances[0].calls) == 2


def test_configure_supports_explicit_metadata_arguments() -> None:
    clean_url, params = cloudsql.configure_cloudsql(
        "postgresql+pg8000://sa@/db",
        instance="proj:reg:inst",
        ip_type="private",
        enable_iam_auth=True,
    )

    assert clean_url == make_url("postgresql+pg8000://sa@/db")
    assert params["creator"]() == (
        "proj:reg:inst",
        "pg8000",
        {"user": "sa", "db": "db"},
    )


def test_configure_rejects_psycopg2() -> None:
    with pytest.raises(ValueError, match="pg8000"):
        cloudsql.configure_cloudsql(
            "postgresql+psycopg2://sa@/db?cloudsql_instance=proj:reg:inst"
        )


def test_configure_explicit_driver_rewrites_uri() -> None:
    clean_url, params = cloudsql.configure_cloudsql(
        "postgresql+psycopg2://sa@/db?"
        "cloudsql_instance=proj:reg:inst&cloudsql_driver=pg8000"
    )

    assert clean_url.get_driver_name() == "pg8000"
    assert params["creator"].driver == "pg8000"


def test_configure_normalizes_string_iam_flag() -> None:
    _, params = cloudsql.configure_cloudsql(
        "mysql+pymysql://user:secret@/db?cloudsql_instance=proj:reg:inst",
        enable_iam_auth="false",
    )

    assert params["creator"].enable_iam_auth is False
    assert params["creator"]() == (
        "proj:reg:inst",
        "pymysql",
        {"client_flag": 2, "user": "user", "db": "db", "password": "secret"},
    )


def test_configure_rejects_driver_for_wrong_backend() -> None:
    with pytest.raises(ValueError, match="pymysql"):
        cloudsql.configure_cloudsql(
            "mysql+pymysql://user:secret@/db?"
            "cloudsql_instance=proj:reg:inst&cloudsql_driver=pg8000"
        )


def test_tls_options_are_not_forwarded() -> None:
    _, params = cloudsql.configure_cloudsql(
        "postgresql+pg8000://sa@/db?"
        "cloudsql_instance=proj:reg:inst&sslmode=require&application_name=superset",
        connect_args={"sslmode": "require", "sslrootcert": "/ca", "timeout": 10},
    )

    _, _, kwargs = params["creator"]()
    assert "sslmode" not in kwargs
    assert "sslrootcert" not in kwargs
    assert kwargs["application_name"] == "superset"
    assert kwargs["timeout"] == 10


def test_mysql_url_options_are_coerced() -> None:
    _, params = cloudsql.configure_cloudsql(
        "mysql+pymysql://user:secret@/db?"
        "cloudsql_instance=proj:reg:inst&connect_timeout=10&local_infile=0"
    )

    _, _, kwargs = params["creator"]()
    assert kwargs["connect_timeout"] == 10
    assert kwargs["local_infile"] is False
    assert kwargs["client_flag"] & 2


def test_mysql_tls_options_are_not_forwarded() -> None:
    _, params = cloudsql.configure_cloudsql(
        "mysql+pymysql://user:secret@/db?cloudsql_instance=proj:reg:inst",
        connect_args={"ssl_verify_cert": True, "read_timeout": 30},
    )

    _, _, kwargs = params["creator"]()
    assert "ssl_verify_cert" not in kwargs
    assert kwargs["read_timeout"] == 30


def test_metadata_uri_is_a_string() -> None:
    uri, params = cloudsql.configure_cloudsql_uri(
        "postgresql+pg8000://sa@/db",
        instance="proj:reg:inst",
        enable_iam_auth=True,
    )

    assert isinstance(uri, str)
    assert uri == "postgresql+pg8000://sa@/db"
    assert "creator" in params


def test_metadata_uri_from_query_parameters() -> None:
    uri, params = cloudsql.configure_cloudsql_uri(
        "postgresql+pg8000://sa@/db?"
        "cloudsql_instance=proj:reg:inst&"
        "cloudsql_ip_type=PRIVATE&"
        "cloudsql_enable_iam_auth=true"
    )

    assert uri == "postgresql+pg8000://sa@/db"
    assert params["creator"].ip_type == "PRIVATE"
    assert params["creator"].enable_iam_auth is True


def test_reset_after_fork_drops_cached_connectors() -> None:
    _, params = cloudsql.configure_cloudsql(
        "mysql+pymysql://user:secret@/db?cloudsql_instance=proj:reg:inst"
    )
    creator = params["creator"]
    creator()

    assert creator._connector is not None
    cloudsql._reset_after_fork()

    assert creator._connector is None
    assert cloudsql._CONNECTORS == {}


def test_connector_authorization_errors_propagate(
    mocker: MockerFixture,
) -> None:
    _, params = cloudsql.configure_cloudsql(
        "mysql+pymysql://user:secret@/db?cloudsql_instance=proj:reg:inst"
    )
    creator = params["creator"]
    mocker.patch.object(
        FakeConnector,
        "connect",
        side_effect=ConnectionRefusedError("connection denied"),
    )

    with pytest.raises(ConnectionRefusedError, match="connection denied"):
        creator()


def test_configure_requires_instance() -> None:
    with pytest.raises(ValueError, match="cloudsql_instance"):
        cloudsql.configure_cloudsql("postgresql+pg8000://sa@/db?cloudsql_instance=")


def test_configure_requires_database() -> None:
    with pytest.raises(ValueError, match="database"):
        cloudsql.configure_cloudsql(
            "postgresql+pg8000://sa@/?cloudsql_instance=proj:reg:inst"
        )


def test_configure_rejects_invalid_timeout() -> None:
    with pytest.raises(ValueError, match="timeout"):
        cloudsql.configure_cloudsql(
            "postgresql+pg8000://sa@/db?"
            "cloudsql_instance=proj:reg:inst&cloudsql_timeout=soon"
        )


def test_mutator_leaves_non_cloudsql_uris_alone() -> None:
    uri = make_url("postgresql+psycopg2://user:pass@host/db")
    params = {"pool_size": 5}

    assert cloudsql.cloudsql_connection_mutator(uri, params, "user", None, None) == (
        uri,
        params,
    )


def test_mutator_merges_engine_params() -> None:
    uri = make_url("mysql+pymysql://user:secret@/db?cloudsql_instance=proj:reg:inst")

    clean_url, params = cloudsql.cloudsql_connection_mutator(
        uri, {"pool_size": 5}, "user", None, None
    )

    assert clean_url.query == {}
    assert params["pool_size"] == 5
    assert "creator" in params


def test_with_cloudsql_wraps_existing_mutator() -> None:
    calls = []

    def existing(uri, params, username, security_manager, source):
        calls.append((uri, params))
        return uri, params

    uri = make_url("mysql+pymysql://user:secret@/db?cloudsql_instance=proj:reg:inst")
    original_query = dict(uri.query)
    clean_url, params = cloudsql.with_cloudsql(existing)(uri, {}, "user", None, None)

    assert clean_url.query == {}
    assert calls
    assert calls[0][0].query == original_query
    assert "creator" not in calls[0][1]
    assert params["creator"].user == "user"
