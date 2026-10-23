/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import rison from 'rison';
import { SupersetClient } from '@superset-ui/core';

export type ExecutionUserStatus = {
  execution_user: string | null;
  token_present: boolean;
};

export type OAuth2Authorization = {
  url: string;
  tab_id: string;
  redirect_uri: string;
};

export const fetchExecutionUserOptions = async (
  filterValue: string,
  page: number,
  pageSize: number,
) => {
  const query = rison.encode_uri({
    filters: [
      ...(filterValue
        ? [{ col: 'username', opr: 'ct', value: filterValue }]
        : []),
      { col: 'active', opr: 'eq', value: true },
    ],
    columns: ['username'],
    page,
    page_size: pageSize,
    order_column: 'username',
    order_direction: 'asc',
  });
  const response = await SupersetClient.get({
    endpoint: `/api/v1/security/users/?q=${query}`,
  });
  return {
    data: (response.json?.result ?? []).map((user: { username: string }) => ({
      value: user.username,
      label: user.username,
    })),
    totalCount: response.json?.count ?? 0,
  };
};

export const fetchExecutionUserStatus = (datasetId: number) =>
  SupersetClient.get({
    endpoint: `/api/v1/dataset/${datasetId}/execution_user_status`,
  }).then(({ json }) => json as ExecutionUserStatus);

export const authorizeExecutionUser = (datasetId: number) =>
  SupersetClient.post({
    endpoint: `/api/v1/dataset/${datasetId}/authorize_execution_user`,
    jsonPayload: {},
  }).then(({ json }) => json as OAuth2Authorization);
