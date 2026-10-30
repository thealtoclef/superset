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

import logging
import os
from typing import Any

from superset.stats_logger import BaseStatsLogger
from superset.utils.log import DBEventLogger

logger = logging.getLogger(__name__)

_METER_PROVIDERS: list[Any] = []


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def create_otel_meter(
    endpoint: str,
    service_name: str = "superset",
    export_interval_millis: int = 5000,
    use_grpc: bool = True,
) -> Any:
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
        OTLPMetricExporter as GRPCMetricExporter,
    )
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
        OTLPMetricExporter as HTTPMetricExporter,
    )
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource

    exporter = (
        GRPCMetricExporter(endpoint=endpoint)
        if use_grpc
        else HTTPMetricExporter(endpoint=endpoint)
    )
    reader = PeriodicExportingMetricReader(
        exporter, export_interval_millis=export_interval_millis
    )
    provider = MeterProvider(
        resource=Resource.create({"service.name": service_name}),
        metric_readers=[reader],
    )
    _METER_PROVIDERS.append(provider)
    return provider.get_meter(name=service_name)


class OtelStatsLogger(BaseStatsLogger):
    def __init__(self, otel_meter: Any, prefix: str = "superset") -> None:
        super().__init__(prefix=prefix)
        self._meter = otel_meter
        self._updown_counters: dict[str, Any] = {}
        self._histograms: dict[str, Any] = {}
        self._gauge_values: dict[str, float] = {}

    def key(self, key: str) -> str:
        prefixed = f"{self.prefix}_{key}" if self.prefix else key
        return prefixed.replace(".", "_").lower()

    def _updown_counter(self, name: str) -> Any:
        if name not in self._updown_counters:
            self._updown_counters[name] = self._meter.create_up_down_counter(
                name=name, unit="1"
            )
        return self._updown_counters[name]

    def _histogram(self, name: str) -> Any:
        if name not in self._histograms:
            self._histograms[name] = self._meter.create_histogram(name=name, unit="ms")
        return self._histograms[name]

    def incr(self, key: str) -> None:
        self._updown_counter(self.key(key)).add(1)

    def decr(self, key: str) -> None:
        self._updown_counter(self.key(key)).add(-1)

    def timing(self, key: str, value: float) -> None:
        self._histogram(self.key(key)).record(value)

    def gauge(self, key: str, value: float) -> None:
        name = self.key(key)
        if name not in self._updown_counters:
            self._updown_counters[name] = self._meter.create_up_down_counter(
                name=name, unit="1"
            )
            self._updown_counters[name].add(value)
        else:
            self._updown_counters[name].add(value - self._gauge_values.get(name, 0))
        self._gauge_values[name] = value


class OtelDBEventLogger(DBEventLogger):
    def __init__(self, otel_meter: Any, prefix: str = "superset") -> None:
        super().__init__()
        self._prefix = f"{prefix}_" if prefix else ""
        self._event_counter = otel_meter.create_counter(
            name=f"{self._prefix}event_total",
            unit="1",
            description="Total number of Superset events",
        )
        self._duration_histogram = otel_meter.create_histogram(
            name=f"{self._prefix}event_duration",
            unit="ms",
            description="Duration of Superset events in milliseconds",
        )

    @staticmethod
    def _record_id(record: Any, key: str) -> Any:
        return record.get(key) if isinstance(record, dict) else None

    def _attributes(
        self,
        record: Any,
        user_id: int | None,
        action: str,
        dashboard_id: int | None,
        slice_id: int | None,
        referrer: str | None,
        **kwargs: Any,
    ) -> dict[str, str]:
        from superset import db, security_manager
        from superset.models.dashboard import Dashboard
        from superset.models.slice import Slice

        dashboard_id = dashboard_id or self._record_id(record, "dashboard_id")
        slice_id = slice_id or self._record_id(record, "slice_id")
        user = db.session.get(security_manager.user_model, user_id) if user_id else None
        dashboard = db.session.get(Dashboard, dashboard_id) if dashboard_id else None
        slice_ = db.session.get(Slice, slice_id) if slice_id else None
        values = {
            "action": action,
            "dashboard_id": dashboard_id,
            "slice_id": slice_id,
            "referrer": referrer,
            "user_id": user_id,
            "dashboard_title": dashboard.dashboard_title if dashboard else None,
            "slice_name": slice_.slice_name if slice_ else None,
            "user_email": user.email if user else None,
            "database_id": kwargs.get("database_id"),
            "engine": kwargs.get("engine"),
            "database_driver": kwargs.get("database_driver"),
        }
        return {key: str(value) for key, value in values.items() if value is not None}

    def log(  # pylint: disable=too-many-arguments
        self,
        user_id: int | None,
        action: str,
        dashboard_id: int | None,
        duration_ms: int | None,
        slice_id: int | None,
        referrer: str | None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        records = kwargs.get("records") or []
        if not records and (curated_payload := kwargs.get("curated_payload")):
            records = [curated_payload]
        for record in records:
            attributes = self._attributes(
                record, user_id, action, dashboard_id, slice_id, referrer, **kwargs
            )
            self._event_counter.add(1, attributes)
            if duration_ms:
                self._duration_histogram.record(duration_ms, attributes)
        super().log(
            user_id,
            action,
            dashboard_id,
            duration_ms,
            slice_id,
            referrer,
            *args,
            **kwargs,
        )


def create_otel_loggers(
    prefix: str | None = None,
) -> tuple[OtelStatsLogger, OtelDBEventLogger]:
    endpoint = os.environ.get("OTEL_ENDPOINT")
    if not endpoint:
        raise RuntimeError(
            "OTEL_ENDPOINT is required when OTEL_LOGGING_ENABLED is true"
        )
    service_name = (
        os.environ.get("OTEL_SERVICE_NAME")
        or os.environ.get("OTEL_SERVICE")
        or "superset"
    )
    interval = int(
        os.environ.get("OTEL_INTERVAL_MILLISECONDS")
        or os.environ.get("OTEL_EXPORT_INTERVAL_MILLIS")
        or "5000"
    )
    meter = create_otel_meter(
        endpoint=endpoint,
        service_name=service_name,
        export_interval_millis=interval,
        use_grpc=_env_bool("OTEL_GRPC", True),
    )
    prefix = prefix if prefix is not None else os.environ.get("OTEL_PREFIX", "superset")
    return OtelStatsLogger(meter, prefix=prefix), OtelDBEventLogger(
        meter, prefix=prefix
    )
