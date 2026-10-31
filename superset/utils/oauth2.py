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

import base64
import hashlib
import logging
import secrets
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator, TYPE_CHECKING, TypeVar

import backoff
import jwt
from flask import current_app as app, g, url_for
from marshmallow import EXCLUDE, fields, post_load, Schema, validate
from sqlalchemy.orm import Session
from werkzeug.routing import BuildError

from superset import db
from superset.distributed_lock import DistributedLock
from superset.exceptions import (
    AcquireDistributedLockFailedException,
    DatasetExecutionUserTokenMissingError,
    OAuth2Error,
    OAuth2TokenRefreshError,
    OAuth2TokenRefreshInProgressError,
)
from superset.superset_typing import OAuth2ClientConfig, OAuth2State
from superset.utils import json
from superset.utils.execution_identity import get_execution_user

if TYPE_CHECKING:
    from superset.db_engine_specs.base import BaseEngineSpec
    from superset.models.core import Database

JWT_EXPIRATION = timedelta(minutes=5)

logger = logging.getLogger(__name__)
T = TypeVar("T")
# Reserved extension-storage namespace for the user's upstream login token.
# The table already exists in Superset 7, so this needs no migration.
UPSTREAM_OAUTH_STORAGE_ID = "superset.oauth2.upstream"


def _upstream_provider(database: Database) -> str | None:
    provider = database.get_upstream_oauth2_provider()
    return provider if isinstance(provider, str) and provider else None


_oauth2_retry_active: ContextVar[bool] = ContextVar(
    "oauth2_retry_active", default=False
)

# PKCE code verifier length (RFC 7636 recommends 43-128 characters)
PKCE_CODE_VERIFIER_LENGTH = 64


def generate_code_verifier() -> str:
    """
    Generate a PKCE code verifier (RFC 7636).

    The code verifier is a high-entropy cryptographic random string using
    unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~",
    with a minimum length of 43 characters and a maximum length of 128.
    """
    # Generate random bytes and encode as URL-safe base64
    random_bytes = secrets.token_bytes(PKCE_CODE_VERIFIER_LENGTH)
    # Use URL-safe base64 encoding without padding
    code_verifier = base64.urlsafe_b64encode(random_bytes).rstrip(b"=").decode("ascii")
    return code_verifier


def generate_code_challenge(code_verifier: str) -> str:
    """
    Generate a PKCE code challenge from a code verifier (RFC 7636).

    Uses the S256 method: BASE64URL(SHA256(code_verifier))
    """
    # Compute SHA-256 hash of the code verifier
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    # Encode as URL-safe base64 without padding
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_challenge


@backoff.on_exception(
    backoff.expo,
    AcquireDistributedLockFailedException,
    factor=0.1,
    base=2,
    max_tries=8,
    raise_on_giveup=False,
    giveup_log_level=logging.DEBUG,
)
def get_oauth2_access_token(
    config: OAuth2ClientConfig,
    database_id: int,
    user_id: int,
    db_engine_spec: type[BaseEngineSpec],
    durable: bool = False,
) -> str | None:
    """
    Return a valid OAuth2 access token.

    If the token exists but is expired and a refresh token is available the function will
    return a fresh token and store it in the database for further requests. The function
    has a retry decorator, in case a dashboard with multiple charts triggers
    simultaneous requests for refreshing a stale token; in that case only the first
    process to acquire the lock will perform the refresh, and other processes should find
    a valid token when they retry.
    """  # noqa: E501
    # pylint: disable=import-outside-toplevel
    from superset.models.core import DatabaseUserOAuth2Tokens

    token = (
        db.session.query(DatabaseUserOAuth2Tokens)
        .filter_by(user_id=user_id, database_id=database_id)
        .one_or_none()
    )
    if token is None:
        return None

    if token.access_token and datetime.now() < token.access_token_expiration:
        return token.access_token

    if token.refresh_token:
        return refresh_oauth2_token(
            config, database_id, user_id, db_engine_spec, durable=durable
        )

    # since the access token is expired and there's no refresh token, delete the entry
    db.session.delete(token)

    return None


def has_stored_oauth2_token(database_id: int, user_id: int) -> bool:
    # pylint: disable=import-outside-toplevel
    from superset.models.core import DatabaseUserOAuth2Tokens

    return (
        db.session.query(DatabaseUserOAuth2Tokens.id)
        .filter_by(user_id=user_id, database_id=database_id)
        .first()
        is not None
    )


def refresh_oauth2_token(  # noqa: C901
    config: OAuth2ClientConfig,
    database_id: int,
    user_id: int,
    db_engine_spec: type[BaseEngineSpec],
    *,
    force: bool = False,
    durable: bool = False,
    rejected_access_token: str | None = None,
) -> str | None:
    # Owner-mode refreshes use an isolated transaction so rotated tokens become
    # durable before the lock is released without committing unrelated work in
    # the caller's scoped session.
    isolated = force or durable
    token_session = Session(bind=db.session.get_bind()) if isolated else db.session
    try:
        return _refresh_oauth2_token_locked(
            config,
            database_id,
            user_id,
            db_engine_spec,
            token_session,
            force=force,
            durable=isolated,
            rejected_access_token=rejected_access_token,
        )
    finally:
        if isolated:
            token_session.close()


def _refresh_oauth2_token_locked(  # noqa: C901
    config: OAuth2ClientConfig,
    database_id: int,
    user_id: int,
    db_engine_spec: type[BaseEngineSpec],
    token_session: Session,
    *,
    force: bool,
    durable: bool,
    rejected_access_token: str | None,
) -> str | None:
    """Refresh a token while serializing and durably persisting the exchange."""
    # pylint: disable=import-outside-toplevel
    from superset.models.core import DatabaseUserOAuth2Tokens

    # Use longer TTL for OAuth2 token refresh (may involve network calls)
    with DistributedLock(
        namespace="refresh_oauth2_token",
        ttl_seconds=30,
        user_id=user_id,
        database_id=database_id,
    ):
        # Short circuit in case another request already deleted the token
        query = token_session.query(DatabaseUserOAuth2Tokens)
        if force:
            query = query.populate_existing()
        token = query.filter_by(user_id=user_id, database_id=database_id).one_or_none()
        if token is None:
            return None

        # Another request may have refreshed the token while this caller waited
        # for the distributed lock. Reuse the winner rather than exchanging a
        # rotating/single-use refresh token again.
        if (
            force
            and rejected_access_token is not None
            and token.access_token != rejected_access_token
        ):
            return token.access_token

        if (
            not force
            and token.access_token
            and datetime.now() < token.access_token_expiration
        ):
            return token.access_token

        if not token.refresh_token:
            token_session.delete(token)
            if durable:
                token_session.commit()  # pylint: disable=consider-using-transaction
            return None

        try:
            token_response = db_engine_spec.get_oauth2_fresh_token(
                config,
                token.refresh_token,
            )
        except db_engine_spec.oauth2_exception as ex:
            # OAuth token is no longer valid, delete it and start OAuth2 dance
            logger.warning(
                "OAuth2 token refresh failed: database_id=%s engine=%s error_type=%s; "
                "deleting token",
                database_id,
                db_engine_spec.engine,
                type(ex).__name__,
            )
            token_session.delete(token)
            token_session.flush()
            if durable:
                token_session.commit()  # pylint: disable=consider-using-transaction
            raise OAuth2TokenRefreshError() from None
        # Engine specs can delegate to arbitrary provider clients that do not share an
        # exception base class. Sanitize every other provider-boundary failure while
        # preserving the refresh token for a later retry.
        except Exception as ex:  # pylint: disable=broad-except
            logger.error(
                "OAuth2 token refresh failed: database_id=%s engine=%s error_type=%s",
                database_id,
                db_engine_spec.engine,
                type(ex).__name__,
            )
            raise OAuth2Error("Token refresh failed") from None

        # The refresh token was revoked if the provider returns no access token;
        # remove the unusable row so callers report a missing authorization.
        if "access_token" not in token_response:
            token_session.delete(token)
            token_session.flush()
            if durable:
                token_session.commit()  # pylint: disable=consider-using-transaction
            return None

        token.access_token = token_response["access_token"]
        token.access_token_expiration = datetime.now() + timedelta(
            seconds=token_response["expires_in"]
        )
        # Support single-use refresh tokens
        if new_refresh_token := token_response.get("refresh_token"):
            token.refresh_token = new_refresh_token

        token_session.add(token)
        if durable:
            # Make rotated access and refresh tokens visible to other workers
            # before releasing the distributed lock.
            token_session.commit()  # pylint: disable=consider-using-transaction

    return token.access_token


def execute_with_oauth2_retry(  # noqa: C901
    database: Database,
    operation: Callable[[], T],
    can_retry: Callable[[], bool] | None = None,
    execution_user: Any | None = None,
) -> T:
    """Refresh a rejected access token and retry an operation once."""
    # pylint: disable=import-outside-toplevel
    from superset.models.core import DatabaseUserOAuth2Tokens

    if database.get_oauth2_config() is None:
        return operation()

    # Upstream login tokens are not refreshed through the database's OAuth2
    # client. Do not let a rejected token start a second database OAuth flow.
    if _upstream_provider(database) is not None:
        return operation()

    execution_user = execution_user or get_execution_user()
    if execution_user is not None:
        user_id = execution_user.id
    else:
        user = getattr(g, "user", None)
        user_id = getattr(user, "id", None)
    rejected_access_token = None
    if user_id is not None:
        with db.session.no_autoflush:
            token = (
                db.session.query(DatabaseUserOAuth2Tokens)
                .filter_by(user_id=user_id, database_id=database.id)
                .one_or_none()
            )
        rejected_access_token = token.access_token if token is not None else None

    retry_context = _oauth2_retry_active.set(True)
    try:
        try:
            return operation()
        finally:
            _oauth2_retry_active.reset(retry_context)
    except Exception as ex:
        oauth2_configured = (
            database.get_oauth2_config() is not None
            if execution_user is not None
            else database.is_oauth2_enabled()
        )
        is_oauth2_error = oauth2_configured and database.db_engine_spec.needs_oauth2(ex)
        if not is_oauth2_error:
            raise
        if execution_user is not None:
            caller_id = getattr(getattr(g, "user", None), "id", None)
            if caller_id is not None and caller_id != execution_user.id:
                app.config["STATS_LOGGER"].incr(
                    "oauth2.forced_refresh.skipped_non_owner"
                )
                raise DatasetExecutionUserTokenMissingError(
                    execution_user.username, database.name
                ) from ex
        if can_retry is not None and not can_retry():
            app.config["STATS_LOGGER"].incr(
                "oauth2.forced_refresh.query_retry_skipped_progress"
            )
            if execution_user is not None:
                raise DatasetExecutionUserTokenMissingError(
                    execution_user.username, database.name
                ) from ex
            database.start_oauth2_dance()
            raise

        config = database.get_oauth2_config()
        if config is None or user_id is None:
            app.config["STATS_LOGGER"].incr("oauth2.forced_refresh.unavailable")
            raise

        stats_logger = app.config["STATS_LOGGER"]
        stats_logger.incr("oauth2.forced_refresh.exchange_attempt")
        logger.info(
            "Forcing OAuth2 token refresh after authentication failure: "
            "database_id=%s engine=%s",
            database.id,
            database.db_engine_spec.engine,
        )
        try:
            access_token = refresh_oauth2_token(
                config,
                database.id,
                user_id,
                database.db_engine_spec,
                force=True,
                rejected_access_token=rejected_access_token,
            )
        except OAuth2TokenRefreshError:
            stats_logger.incr("oauth2.forced_refresh.exchange_rejected")
            if execution_user is not None:
                raise DatasetExecutionUserTokenMissingError(
                    execution_user.username, database.name
                ) from None
            database.start_oauth2_dance()
            raise
        except AcquireDistributedLockFailedException:
            if execution_user is not None:
                raise OAuth2TokenRefreshInProgressError() from None
            raise
        except Exception:
            stats_logger.incr("oauth2.forced_refresh.exchange_transient_failure")
            raise

        if access_token is None:
            stats_logger.incr("oauth2.forced_refresh.unavailable")
            if execution_user is not None:
                raise DatasetExecutionUserTokenMissingError(
                    execution_user.username, database.name
                ) from None
            database.start_oauth2_dance()

        # The forced refresh commits through an isolated session. Expire the token
        # loaded above so connection creation for the retry observes that commit.
        if token is not None:
            db.session.expire(token)

        stats_logger.incr("oauth2.forced_refresh.exchange_success")
        try:
            result = operation()
        except Exception:
            stats_logger.incr("oauth2.forced_refresh.query_retry_failure")
            raise
        stats_logger.incr("oauth2.forced_refresh.query_retry_success")
        return result


def is_oauth2_retry_active() -> bool:
    """Return whether an outer query execution can retry an OAuth2 failure."""
    return _oauth2_retry_active.get()


def _upstream_token_expiration(
    token_response: dict[str, Any],
) -> datetime | None:
    """Return the absolute expiry for an upstream token response."""
    expires_in = token_response.get("expires_in")
    if expires_in is None:
        return None
    try:
        seconds = int(expires_in)
    except (TypeError, ValueError):
        logger.warning("Ignoring non-numeric OAuth2 expires_in value")
        return None
    return datetime.now(tz=timezone.utc) + timedelta(seconds=seconds)


def _serialize_upstream_token(
    token_response: dict[str, Any],
    previous_refresh_token: str | None = None,
) -> dict[str, Any]:
    expires_at = _upstream_token_expiration(token_response)
    return {
        "access_token": token_response.get("access_token"),
        "access_token_expiration": expires_at.isoformat() if expires_at else None,
        "refresh_token": (
            token_response.get("refresh_token") or previous_refresh_token
        ),
    }


def _parse_upstream_token_expiration(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        expires_at = datetime.fromisoformat(value)
    except ValueError:
        logger.warning("Ignoring malformed upstream OAuth2 expiration")
        return None
    return (
        expires_at
        if expires_at.tzinfo is not None
        else expires_at.replace(tzinfo=timezone.utc)
    )


def _get_upstream_token_payload(
    provider: str,
    user_id: int,
) -> dict[str, Any] | None:
    # pylint: disable=import-outside-toplevel
    from superset.extensions.storage.persistent_dao import ExtensionStorageDAO

    try:
        payload = ExtensionStorageDAO.get_decoded_value(
            UPSTREAM_OAUTH_STORAGE_ID,
            provider,
            user_fk=user_id,
        )
    except Exception:  # pylint: disable=broad-except
        logger.warning(
            "Unable to read upstream OAuth2 token for provider %s",
            provider,
            exc_info=True,
        )
        return None
    return payload if isinstance(payload, dict) else None


def save_upstream_provider_token(
    user_id: int,
    provider: str,
    token_response: dict[str, Any],
    previous_refresh_token: str | None = None,
) -> None:
    """
    Persist the login provider's token for a user.

    Stored in the existing encrypted extension-storage table, scoped to the user
    and keyed by provider. There is deliberately no database migration.
    """
    payload = _serialize_upstream_token(token_response, previous_refresh_token)
    if not payload["access_token"]:
        logger.warning(
            "OAuth provider %s returned no access token; not storing it",
            provider,
        )
        return

    # pylint: disable=import-outside-toplevel
    from superset.extensions.storage.persistent_dao import ExtensionStorageDAO

    ExtensionStorageDAO.set(
        UPSTREAM_OAUTH_STORAGE_ID,
        provider,
        json.dumps(payload).encode("utf-8"),
        codec="json",
        user_fk=user_id,
        encrypt=True,
    )


def _delete_upstream_provider_token(provider: str, user_id: int) -> None:
    # pylint: disable=import-outside-toplevel
    from superset.extensions.storage.persistent_dao import ExtensionStorageDAO

    if ExtensionStorageDAO.delete_by_key(
        UPSTREAM_OAUTH_STORAGE_ID,
        provider,
        user_fk=user_id,
    ):
        db.session.commit()  # pylint: disable=consider-using-transaction


def _upstream_token_is_valid(
    payload: dict[str, Any],
) -> tuple[str | None, datetime | None]:
    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        return None, None
    expires_at = _parse_upstream_token_expiration(
        payload.get("access_token_expiration")
    )
    if expires_at is None or datetime.now(tz=timezone.utc) < expires_at:
        return access_token, expires_at
    return None, expires_at


def get_upstream_provider_token(provider: str, user_id: int) -> str | None:
    """
    Return a valid access token from the user's login provider.

    Refreshes an expired token with the provider's refresh token when possible.
    The refresh is serialized across workers so a rotating refresh token is
    exchanged once.
    """
    payload = _get_upstream_token_payload(provider, user_id)
    if payload is None:
        return None

    access_token, _ = _upstream_token_is_valid(payload)
    if access_token:
        return access_token

    refresh_token = payload.get("refresh_token")
    if isinstance(refresh_token, str) and refresh_token:
        return _refresh_upstream_provider_token(provider, user_id, refresh_token)

    _delete_upstream_provider_token(provider, user_id)
    return None


def _refresh_upstream_provider_token(
    provider: str,
    user_id: int,
    refresh_token: str,
) -> str | None:
    """Refresh an upstream token under a per-user/provider lock."""
    with DistributedLock(
        namespace="refresh_upstream_oauth_token",
        ttl_seconds=30,
        user_id=user_id,
        provider=provider,
    ):
        # Another worker may have refreshed the token while this one waited.
        payload = _get_upstream_token_payload(provider, user_id)
        if payload is not None:
            access_token, _ = _upstream_token_is_valid(payload)
            if access_token:
                return access_token
            refresh_token = payload.get("refresh_token") or refresh_token

        remote_app = app.extensions.get("authlib.integrations.flask_client", {}).get(
            provider
        )
        if remote_app is None:
            logger.warning(
                "OAuth provider %s is not configured for token refresh",
                provider,
            )
            _delete_upstream_provider_token(provider, user_id)
            return None

        try:
            token_response = remote_app.fetch_access_token(
                grant_type="refresh_token",
                refresh_token=refresh_token,
            )
        except Exception as ex:  # pylint: disable=broad-except
            # Keep the refresh token on transient failures so a later request
            # can retry. Only a provider rejection means the grant is unusable.
            if getattr(ex, "error", None) in {"invalid_grant", "invalid_token"}:
                _delete_upstream_provider_token(provider, user_id)
            logger.warning(
                "Failed to refresh upstream OAuth2 token for provider %s",
                provider,
                exc_info=True,
            )
            return None

        if not isinstance(token_response, dict) or "access_token" not in token_response:
            _delete_upstream_provider_token(provider, user_id)
            return None

        save_upstream_provider_token(
            user_id,
            provider,
            token_response,
            previous_refresh_token=refresh_token,
        )
        access_token = token_response.get("access_token")
        return access_token if isinstance(access_token, str) else None


def encode_oauth2_state(state: OAuth2State) -> str:
    """
    Encode the OAuth2 state.
    """
    payload: dict[str, Any] = {
        "exp": datetime.now(tz=timezone.utc) + JWT_EXPIRATION,
        "database_id": state["database_id"],
        "user_id": state["user_id"],
        "default_redirect_uri": state["default_redirect_uri"],
        "tab_id": state["tab_id"],
    }

    encoded_state = jwt.encode(
        payload=payload,
        key=app.config["SECRET_KEY"],
        algorithm=app.config["DATABASE_OAUTH2_JWT_ALGORITHM"],
    )

    # Google OAuth2 needs periods to be escaped.
    encoded_state = encoded_state.replace(".", "%2E")

    return encoded_state


class OAuth2StateSchema(Schema):
    database_id = fields.Int(required=True)
    user_id = fields.Int(required=True)
    default_redirect_uri = fields.Str(required=True)
    tab_id = fields.Str(required=True)

    # pylint: disable=unused-argument
    @post_load
    def make_oauth2_state(
        self,
        data: dict[str, Any],
        **kwargs: Any,
    ) -> OAuth2State:
        return {
            "database_id": data["database_id"],
            "user_id": data["user_id"],
            "default_redirect_uri": data["default_redirect_uri"],
            "tab_id": data["tab_id"],
        }

    class Meta:  # pylint: disable=too-few-public-methods
        # ignore `exp`
        unknown = EXCLUDE


oauth2_state_schema = OAuth2StateSchema()


def decode_oauth2_state(encoded_state: str) -> OAuth2State:
    """
    Decode the OAuth2 state.
    """
    # Google OAuth2 needs periods to be escaped.
    encoded_state = encoded_state.replace("%2E", ".")

    payload = jwt.decode(
        jwt=encoded_state,
        key=app.config["SECRET_KEY"],
        algorithms=[app.config["DATABASE_OAUTH2_JWT_ALGORITHM"]],
    )
    state = oauth2_state_schema.load(payload)

    return state


def get_oauth2_redirect_uri() -> str:
    """
    Return the OAuth2 redirect URI.

    Tries the explicit config first, then falls back to url_for().
    If url_for() fails (e.g. in headless/MCP contexts where the
    DatabaseRestApi blueprint may not be registered), raises
    OAuth2Error so callers don't silently proceed with an invalid URI.
    """
    if configured := app.config.get("DATABASE_OAUTH2_REDIRECT_URI"):
        return configured

    try:
        return url_for("DatabaseRestApi.oauth2", _external=True)
    except (BuildError, RuntimeError):
        raise OAuth2Error(
            "Unable to determine the OAuth2 redirect URI. "
            "Set DATABASE_OAUTH2_REDIRECT_URI in the configuration."
        ) from None


class OAuth2ClientConfigSchema(Schema):
    id = fields.String(required=True)
    secret = fields.String(required=True)
    scope = fields.String(required=True)
    redirect_uri = fields.String(
        required=False,
        load_default=get_oauth2_redirect_uri,
    )
    authorization_request_uri = fields.String(required=True)
    token_request_uri = fields.String(required=True)
    request_content_type = fields.String(
        required=False,
        load_default=lambda: "json",
        validate=validate.OneOf(["json", "data"]),
    )


@contextmanager
def check_for_oauth2(
    database: Database, execution_user: Any | None = None
) -> Iterator[None]:
    """
    Run code and check if OAuth2 is needed.
    """
    execution_user = execution_user or get_execution_user()
    try:
        yield
    except Exception as ex:
        if execution_user is not None and isinstance(ex, OAuth2TokenRefreshError):
            raise DatasetExecutionUserTokenMissingError(
                execution_user.username, database.name
            ) from ex
        if (
            not is_oauth2_retry_active()
            and execution_user is None
            and database.is_oauth2_enabled()
            and _upstream_provider(database) is None
            and (
                isinstance(ex, OAuth2TokenRefreshError)
                or database.db_engine_spec.needs_oauth2(ex)
            )
        ):
            database.db_engine_spec.start_oauth2_dance(database)
        raise
