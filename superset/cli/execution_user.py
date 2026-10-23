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
import click
from flask.cli import with_appcontext

from superset import db, security_manager
from superset.utils.execution_identity import supports_execution_user
from superset.utils.oauth2 import has_stored_oauth2_token


@click.command()
@with_appcontext
def dataset_execution_health() -> None:
    """List datasets whose execution user cannot authorize the database."""
    # pylint: disable=import-outside-toplevel
    from superset.connectors.sqla.models import SqlaTable

    issues = 0
    for dataset in db.session.query(SqlaTable).order_by(SqlaTable.id):
        username = dataset.get_execution_user_username()
        if not username:
            continue
        user = security_manager.find_user(username=username)
        if not user or not user.active:
            click.echo(f"{dataset.id}\t{dataset.table_name}\tunknown user {username}")
            issues += 1
        elif not supports_execution_user(dataset.database):
            click.echo(
                f"{dataset.id}\t{dataset.table_name}\t"
                "database does not support OAuth2 impersonation"
            )
            issues += 1
        elif not has_stored_oauth2_token(int(dataset.database_id), int(user.id)):
            click.echo(
                f"{dataset.id}\t{dataset.table_name}\t"
                f"{username} has not authorized {dataset.database.database_name}"
            )
            issues += 1

    if not issues:
        click.secho("All dataset execution users are authorized.", fg="green")
