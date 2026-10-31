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

from superset.databases import alloydb

INSTANCE = "projects/proj/locations/reg/clusters/cluster/instances/inst"


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
    mocker.patch.object(alloydb, "_CONNECTORS", {})
    mocker.patch.object(alloydb, "_connector_class", return_value=FakeConnector)
    return FakeConnector


def test_configure_postgres_iam() -> None:
    clean_url, params = alloydb.configure_alloydb(
        "postgresql+pg8000://sa@/db?"
        f"alloydb_instance={INSTANCE}&"
        "alloydb_ip_type=PUBLIC&"
        "alloydb_enable_iam_auth=true"
    )

    assert clean_url.query == {}
    assert clean_url.username == "sa"
    assert clean_url.database == "db"
    assert params["pool_pre_ping"] is True
    assert params["pool_recycle"] == 1800

    creator = params["creator"]
    assert "iam=True" in repr(creator)
    assert creator() == (INSTANCE, "pg8000", {"user": "sa", "db": "db"})
    assert FakeConnector.instances[0].kwargs == {
        "ip_type": "PUBLIC",
        "enable_iam_auth": True,
    }


def test_configure_postgres_with_password() -> None:
    _, params = alloydb.configure_alloydb(
        f"postgresql+pg8000://user:secret@/db?alloydb_instance={INSTANCE}"
    )

    creator = params["creator"]
    assert creator() == (
        INSTANCE,
        "pg8000",
        {"user": "user", "db": "db", "password": "secret"},
    )
    assert FakeConnector.instances[0].kwargs["ip_type"] == "PRIVATE"
    assert FakeConnector.instances[0].kwargs["enable_iam_auth"] is False


def test_connector_is_cached_per_instance() -> None:
    first_url, first_params = alloydb.configure_alloydb(
        f"postgresql+pg8000://user:secret@/db?alloydb_instance={INSTANCE}"
    )
    second_url, second_params = alloydb.configure_alloydb(
        f"postgresql+pg8000://user:secret@/db?alloydb_instance={INSTANCE}"
    )

    assert first_url == second_url
    first_params["creator"]()
    second_params["creator"]()

    assert len(FakeConnector.instances) == 1
    assert len(FakeConnector.instances[0].calls) == 2


def test_configure_supports_explicit_metadata_arguments() -> None:
    clean_url, params = alloydb.configure_alloydb(
        "postgresql+pg8000://sa@/db",
        instance=INSTANCE,
        ip_type="public",
        enable_iam_auth=True,
    )

    assert clean_url == make_url("postgresql+pg8000://sa@/db")
    assert params["creator"]() == (INSTANCE, "pg8000", {"user": "sa", "db": "db"})


def test_configure_rejects_psycopg2() -> None:
    with pytest.raises(ValueError, match="pg8000"):
        alloydb.configure_alloydb(
            f"postgresql+psycopg2://sa@/db?alloydb_instance={INSTANCE}"
        )


def test_configure_rejects_non_postgres() -> None:
    with pytest.raises(ValueError, match="PostgreSQL"):
        alloydb.configure_alloydb(
            f"mysql+pymysql://user:secret@/db?alloydb_instance={INSTANCE}"
        )


def test_configure_rejects_invalid_ip_type() -> None:
    with pytest.raises(ValueError, match="IP type"):
        alloydb.configure_alloydb(
            f"postgresql+pg8000://sa@/db?alloydb_instance={INSTANCE}"
            "&alloydb_ip_type=LOCAL"
        )


def test_configure_explicit_driver_rewrites_uri() -> None:
    clean_url, params = alloydb.configure_alloydb(
        "postgresql+psycopg2://sa@/db?"
        f"alloydb_instance={INSTANCE}&alloydb_driver=pg8000"
    )

    assert clean_url.get_driver_name() == "pg8000"
    assert params["creator"].driver == "pg8000"


def test_configure_normalizes_string_iam_flag() -> None:
    _, params = alloydb.configure_alloydb(
        f"postgresql+pg8000://user:secret@/db?alloydb_instance={INSTANCE}",
        enable_iam_auth="false",
    )

    assert params["creator"].enable_iam_auth is False
    assert params["creator"]() == (
        INSTANCE,
        "pg8000",
        {"user": "user", "db": "db", "password": "secret"},
    )


def test_tls_options_are_not_forwarded() -> None:
    _, params = alloydb.configure_alloydb(
        f"postgresql+pg8000://sa@/db?alloydb_instance={INSTANCE}"
        "&sslmode=require&application_name=superset",
        connect_args={"sslmode": "require", "sslrootcert": "/ca", "timeout": 10},
    )

    _, _, kwargs = params["creator"]()
    assert "sslmode" not in kwargs
    assert "sslrootcert" not in kwargs
    assert kwargs["application_name"] == "superset"
    assert kwargs["timeout"] == 10


def test_metadata_uri_is_a_string() -> None:
    uri, params = alloydb.configure_alloydb_uri(
        "postgresql+pg8000://sa@/db",
        instance=INSTANCE,
        enable_iam_auth=True,
    )

    assert isinstance(uri, str)
    assert uri == "postgresql+pg8000://sa@/db"
    assert "creator" in params


def test_metadata_uri_from_query_parameters() -> None:
    uri, params = alloydb.configure_alloydb_uri(
        "postgresql+pg8000://sa@/db?"
        f"alloydb_instance={INSTANCE}&"
        "alloydb_ip_type=PUBLIC&"
        "alloydb_enable_iam_auth=true"
    )

    assert uri == "postgresql+pg8000://sa@/db"
    assert params["creator"].ip_type == "PUBLIC"
    assert params["creator"].enable_iam_auth is True


def test_reset_after_fork_drops_cached_connectors() -> None:
    _, params = alloydb.configure_alloydb(
        f"postgresql+pg8000://user:secret@/db?alloydb_instance={INSTANCE}"
    )
    creator = params["creator"]
    creator()

    assert creator._connector is not None
    alloydb._reset_after_fork()

    assert creator._connector is None
    assert alloydb._CONNECTORS == {}


def test_connector_authorization_errors_propagate(
    mocker: MockerFixture,
) -> None:
    _, params = alloydb.configure_alloydb(
        f"postgresql+pg8000://user:secret@/db?alloydb_instance={INSTANCE}"
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
    with pytest.raises(ValueError, match="alloydb_instance"):
        alloydb.configure_alloydb("postgresql+pg8000://sa@/db?alloydb_instance=")


def test_configure_requires_database() -> None:
    with pytest.raises(ValueError, match="database"):
        alloydb.configure_alloydb(
            f"postgresql+pg8000://sa@/?alloydb_instance={INSTANCE}"
        )


def test_mutator_leaves_non_alloydb_uris_alone() -> None:
    uri = make_url("postgresql+pg8000://user:pass@host/db")
    params = {"pool_size": 5}

    assert alloydb.alloydb_connection_mutator(uri, params, "user", None, None) == (
        uri,
        params,
    )


def test_mutator_merges_engine_params() -> None:
    uri = make_url(f"postgresql+pg8000://user:secret@/db?alloydb_instance={INSTANCE}")

    clean_url, params = alloydb.alloydb_connection_mutator(
        uri, {"pool_size": 5}, "user", None, None
    )

    assert clean_url.query == {}
    assert params["pool_size"] == 5
    assert "creator" in params


def test_with_alloydb_wraps_existing_mutator() -> None:
    calls = []

    def existing(uri, params, username, security_manager, source):
        calls.append((uri, params))
        return uri, params

    uri = make_url(f"postgresql+pg8000://user:secret@/db?alloydb_instance={INSTANCE}")
    original_query = dict(uri.query)
    clean_url, params = alloydb.with_alloydb(existing)(uri, {}, "user", None, None)

    assert clean_url.query == {}
    assert calls
    assert calls[0][0].query == original_query
    assert "creator" not in calls[0][1]
    assert params["creator"].user == "user"
