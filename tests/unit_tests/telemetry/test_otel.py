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
from pytest_mock import MockerFixture

from superset.telemetry.otel import (
    create_otel_loggers,
    OtelDBEventLogger,
    OtelStatsLogger,
)


class FakeInstrument:
    def __init__(self) -> None:
        self.values: list[Any] = []

    def add(self, value: Any, attributes: dict[str, Any] | None = None) -> None:
        self.values.append(value)

    def record(self, value: Any, attributes: dict[str, Any] | None = None) -> None:
        self.values.append(value)


class FakeMeter:
    def __init__(self) -> None:
        self.counters: dict[str, FakeInstrument] = {}
        self.histograms: dict[str, FakeInstrument] = {}

    def create_up_down_counter(self, name: str, unit: str | None = None) -> Any:
        return self.counters.setdefault(name, FakeInstrument())

    def create_counter(self, name: str, **kwargs: Any) -> Any:
        return self.counters.setdefault(name, FakeInstrument())

    def create_histogram(self, name: str, **kwargs: Any) -> Any:
        return self.histograms.setdefault(name, FakeInstrument())


def test_stats_logger_records() -> None:
    meter = FakeMeter()
    stats = OtelStatsLogger(meter, prefix="superset")

    stats.incr("a.b")
    stats.decr("a.b")
    stats.timing("query.time", 12.0)
    stats.gauge("queue.depth", 5)
    stats.gauge("queue.depth", 8)

    assert meter.counters["superset_a_b"].values == [1, -1]
    assert meter.counters["superset_queue_depth"].values == [5, 3]
    assert meter.histograms["superset_query_time"].values == [12.0]


def test_event_logger_emits_and_logs_to_db(
    mocker: MockerFixture,
) -> None:
    meter = FakeMeter()
    event_logger = OtelDBEventLogger(meter, prefix="superset")
    mocker.patch.object(event_logger, "_attributes", return_value={"action": "explore"})
    db_log = mocker.patch("superset.telemetry.otel.DBEventLogger.log")

    event_logger.log(
        user_id=1,
        action="explore",
        dashboard_id=2,
        duration_ms=10,
        slice_id=3,
        referrer=None,
        records=[{"dashboard_id": 2}],
    )

    assert meter.counters["superset_event_total"].values == [1]
    assert meter.histograms["superset_event_duration"].values == [10]
    db_log.assert_called_once()


def test_event_logger_attributes(
    mocker: MockerFixture,
) -> None:
    event_logger = OtelDBEventLogger(FakeMeter(), prefix="superset")
    mocker.patch(
        "superset.db.session.get",
        side_effect=[
            SimpleNamespace(email="alice@example.com"),
            SimpleNamespace(dashboard_title="Sales"),
            SimpleNamespace(slice_name="Revenue"),
        ],
    )

    attributes = event_logger._attributes(
        {"dashboard_id": 2, "slice_id": 3},
        user_id=1,
        action="explore",
        dashboard_id=None,
        slice_id=None,
        referrer="https://example.com",
        database_id=4,
    )

    assert attributes == {
        "action": "explore",
        "dashboard_id": "2",
        "slice_id": "3",
        "referrer": "https://example.com",
        "user_id": "1",
        "dashboard_title": "Sales",
        "slice_name": "Revenue",
        "user_email": "alice@example.com",
        "database_id": "4",
    }


def test_create_otel_loggers_requires_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OTEL_ENDPOINT", raising=False)

    with pytest.raises(RuntimeError, match="OTEL_ENDPOINT"):
        create_otel_loggers()
