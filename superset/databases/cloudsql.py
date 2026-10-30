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

import os
import threading
import weakref
from typing import Any, Callable, TYPE_CHECKING

from sqlalchemy.engine.url import URL
from sqlalchemy.util import coerce_kw_type

from superset.databases.utils import make_url_safe

if TYPE_CHECKING:
    from superset.security.manager import SupersetSecurityManager

CLOUDSQL_QUERY_PREFIX = "cloudsql_"
CLOUDSQL_INSTANCE = "cloudsql_instance"
CLOUDSQL_DRIVER = "cloudsql_driver"
CLOUDSQL_IP_TYPE = "cloudsql_ip_type"
CLOUDSQL_IAM_AUTH = "cloudsql_enable_iam_auth"
CLOUDSQL_TIMEOUT = "cloudsql_timeout"

_MYSQL_DRIVERS = frozenset({"pymysql"})
_POSTGRES_DRIVERS = frozenset({"pg8000"})
_IP_TYPES = frozenset({"PUBLIC", "PRIVATE", "PSC"})
_DEFAULT_IP_TYPE = "PUBLIC"
_DEFAULT_TIMEOUT = 30
_TLS_CONNECT_ARGS = frozenset(
    {
        "ssl",
        "ssl_ca",
        "ssl_cert",
        "ssl_check_hostname",
        "ssl_context",
        "ssl_disabled",
        "ssl_key",
        "ssl_mode",
        "ssl_verify_cert",
        "ssl_verify_identity",
        "sslcert",
        "sslkey",
        "sslmode",
        "sslrootcert",
    }
)

ConnectionMutator = Callable[
    [URL, dict[str, Any], str | None, "SupersetSecurityManager", Any],
    tuple[URL, dict[str, Any]],
]

_CONNECTORS: dict[tuple[str, str, bool, int], Any] = {}
_CONNECTORS_LOCK = threading.Lock()
_CREATORS: weakref.WeakSet[Any] = weakref.WeakSet()


def _query_value(url: URL, key: str) -> str | None:
    value = url.query.get(key)
    if isinstance(value, tuple):
        value = value[0] if value else None
    return str(value) if value is not None else None


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Invalid boolean value: {value!r}")


def _connector_class() -> Any:
    from google.cloud.sql.connector import Connector

    return Connector


def _get_connector(
    instance: str,
    ip_type: str,
    enable_iam_auth: bool,
    timeout: int,
) -> Any:
    key = (instance, ip_type, enable_iam_auth, timeout)
    with _CONNECTORS_LOCK:
        connector = _CONNECTORS.get(key)
        if connector is None:
            connector = _connector_class()(
                ip_type=ip_type,
                enable_iam_auth=enable_iam_auth,
                timeout=timeout,
            )
            _CONNECTORS[key] = connector
        return connector


class CloudSQLCreator:
    """SQLAlchemy DBAPI creator backed by one connector per instance."""

    def __init__(
        self,
        instance: str,
        driver: str,
        user: str,
        database: str | None,
        password: str | None,
        *,
        ip_type: str = _DEFAULT_IP_TYPE,
        enable_iam_auth: bool = False,
        timeout: int = _DEFAULT_TIMEOUT,
        connect_args: dict[str, Any] | None = None,
    ) -> None:
        self.instance = instance
        self.driver = driver
        self.user = user
        self.database = database
        self.password = password
        self.ip_type = ip_type
        self.enable_iam_auth = enable_iam_auth
        self.timeout = timeout
        self.connect_args = dict(connect_args or {})
        self._connector: Any | None = None
        self._lock = threading.Lock()
        _CREATORS.add(self)

    def _reset_after_fork(self) -> None:
        self._connector = None
        self._lock = threading.Lock()

    def _get(self) -> Any:
        if self._connector is None:
            with self._lock:
                if self._connector is None:
                    self._connector = _get_connector(
                        self.instance,
                        self.ip_type,
                        self.enable_iam_auth,
                        self.timeout,
                    )
        return self._connector

    def __call__(self) -> Any:
        kwargs = dict(self.connect_args)
        kwargs["user"] = self.user
        if self.database is not None:
            kwargs["db"] = self.database
        if self.enable_iam_auth:
            kwargs.pop("password", None)
        elif self.password is not None:
            kwargs["password"] = self.password
        return self._get().connect(self.instance, self.driver, **kwargs)

    def __repr__(self) -> str:
        options = {
            key: value
            for key, value in sorted(self.connect_args.items())
            if key != "password"
        }
        return (
            f"<CloudSQLCreator driver={self.driver} instance={self.instance} "
            f"database={self.database!r} iam={self.enable_iam_auth} "
            f"ip_type={self.ip_type} timeout={self.timeout} "
            f"options={options!r}>"
        )


def _resolve_driver(url: URL, driver: str | None) -> str:
    backend = url.get_backend_name()
    resolved = driver or url.get_driver_name()
    if backend == "mysql":
        if resolved not in _MYSQL_DRIVERS:
            raise ValueError(
                f"Cloud SQL for MySQL requires the pymysql driver; got {resolved!r}"
            )
    elif backend == "postgresql":
        if resolved not in _POSTGRES_DRIVERS:
            raise ValueError(
                f"Cloud SQL for PostgreSQL requires pg8000; got {resolved!r}"
            )
    else:
        raise ValueError(
            "Cloud SQL connector supports only MySQL and PostgreSQL URIs; "
            f"got {backend!r}"
        )
    return resolved


_CONNECTOR_OWNED_ARGS = frozenset(
    {"database", "db", "host", "passwd", "password", "port", "user"}
)
_MYSQL_TYPED_ARGS = {
    "client_flag": int,
    "compress": bool,
    "connect_timeout": int,
    "local_infile": bool,
    "read_timeout": int,
    "use_unicode": bool,
    "write_timeout": int,
}


def _driver_connect_args(url: URL, driver: str) -> dict[str, Any]:
    """Build driver kwargs with SQLAlchemy's dialect coercions."""
    dialect_cls = url.get_dialect()
    try:
        dialect = dialect_cls(**{"dbapi": dialect_cls.import_dbapi()})
        _, args = dialect.create_connect_args(url)
    except (ImportError, ModuleNotFoundError):
        # The connector extra may not install the DBAPI in minimal test
        # environments. Preserve URL options with the same common coercions.
        args = dict(url.query)
        if driver == "pymysql":
            for key, kw_type in _MYSQL_TYPED_ARGS.items():
                coerce_kw_type(args, key, kw_type)
            try:
                from pymysql.constants import CLIENT
            except ImportError:
                found_rows = 2
            else:
                found_rows = CLIENT.FOUND_ROWS
            args["client_flag"] = int(args.get("client_flag", 0)) | found_rows
    return {
        key: value
        for key, value in args.items()
        if key not in _CONNECTOR_OWNED_ARGS
        and key not in _TLS_CONNECT_ARGS
        and not key.startswith(CLOUDSQL_QUERY_PREFIX)
    }


def configure_cloudsql(
    uri: str | URL,
    *,
    instance: str | None = None,
    driver: str | None = None,
    ip_type: str | None = None,
    enable_iam_auth: bool | None = None,
    timeout: int | None = None,
    connect_args: dict[str, Any] | None = None,
) -> tuple[URL, dict[str, Any]]:
    """Strip Cloud SQL parameters and return SQLAlchemy engine options.

    Cloud SQL-specific query parameters are removed before the URL is passed to
    ``create_engine``. Non-IAM passwords remain in the returned URL; the
    returned options contain the DBAPI ``creator``.
    """
    url = make_url_safe(uri) if not isinstance(uri, URL) else uri
    instance = instance or _query_value(url, CLOUDSQL_INSTANCE)
    if not instance:
        raise ValueError(f"{CLOUDSQL_INSTANCE} is required")
    if not url.username:
        raise ValueError("Cloud SQL connections require a username")
    if not url.database:
        raise ValueError("Cloud SQL connections require a database")

    resolved_driver = _resolve_driver(url, driver or _query_value(url, CLOUDSQL_DRIVER))
    if resolved_driver != url.get_driver_name():
        url = url.set(drivername=f"{url.get_backend_name()}+{resolved_driver}")
    resolved_ip_type = (
        ip_type or _query_value(url, CLOUDSQL_IP_TYPE) or _DEFAULT_IP_TYPE
    ).upper()
    if resolved_ip_type not in _IP_TYPES:
        raise ValueError(f"Unsupported Cloud SQL IP type: {resolved_ip_type}")

    iam_default = _as_bool(_query_value(url, CLOUDSQL_IAM_AUTH))
    resolved_iam_auth = (
        iam_default
        if enable_iam_auth is None
        else _as_bool(enable_iam_auth, iam_default)
    )
    timeout_value = (
        timeout if timeout is not None else _query_value(url, CLOUDSQL_TIMEOUT)
    )
    try:
        resolved_timeout = int(
            _DEFAULT_TIMEOUT if timeout_value is None else timeout_value
        )
    except (TypeError, ValueError) as ex:
        raise ValueError(f"Invalid Cloud SQL timeout: {timeout_value!r}") from ex
    if resolved_timeout <= 0:
        raise ValueError(f"Invalid Cloud SQL timeout: {timeout_value!r}")

    driver_connect_args = _driver_connect_args(url, resolved_driver)
    explicit_connect_args = {
        key: value
        for key, value in (connect_args or {}).items()
        if key not in _CONNECTOR_OWNED_ARGS and key not in _TLS_CONNECT_ARGS
    }
    clean_url = url.difference_update_query(list(url.query))

    creator = CloudSQLCreator(
        instance,
        resolved_driver,
        clean_url.username or "",
        clean_url.database,
        None if resolved_iam_auth else clean_url.password,
        ip_type=resolved_ip_type,
        enable_iam_auth=resolved_iam_auth,
        timeout=resolved_timeout,
        connect_args={**driver_connect_args, **explicit_connect_args},
    )
    return clean_url, {
        "creator": creator,
        "pool_pre_ping": True,
        "pool_recycle": 1800,
    }


def cloudsql_connection_mutator(
    uri: URL,
    params: dict[str, Any],
    username: str | None,
    security_manager: SupersetSecurityManager,
    source: Any,
) -> tuple[URL, dict[str, Any]]:
    """Apply Cloud SQL settings when the URI carries a cloudsql_* parameter."""
    url = make_url_safe(uri) if not isinstance(uri, URL) else uri
    if not any(key.startswith(CLOUDSQL_QUERY_PREFIX) for key in url.query):
        return uri, params

    clean_url, cloud_sql_params = configure_cloudsql(
        url,
        connect_args=params.get("connect_args"),
    )
    return clean_url, {**params, **cloud_sql_params}


def configure_cloudsql_uri(
    uri: str | URL,
    **kwargs: Any,
) -> tuple[str, dict[str, Any]]:
    """Return a rendered URI and engine options for the metadata database."""
    url, options = configure_cloudsql(uri, **kwargs)
    return url.render_as_string(hide_password=False), options


def with_cloudsql(
    mutator: ConnectionMutator | None = None,
) -> ConnectionMutator:
    """Wrap an existing DB_CONNECTION_MUTATOR with Cloud SQL support."""

    def mutate(
        uri: URL,
        params: dict[str, Any],
        username: str | None,
        security_manager: SupersetSecurityManager,
        source: Any,
    ) -> tuple[URL, dict[str, Any]]:
        if mutator is not None:
            uri, params = mutator(uri, params, username, security_manager, source)
        return cloudsql_connection_mutator(
            uri, params, username, security_manager, source
        )

    return mutate


def _reset_after_fork() -> None:
    global _CONNECTORS_LOCK
    _CONNECTORS.clear()
    _CONNECTORS_LOCK = threading.Lock()
    for creator in list(_CREATORS):
        creator._reset_after_fork()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_after_fork)
