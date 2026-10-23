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
import fetchMock from 'fetch-mock';
import { render, screen, userEvent } from 'spec/helpers/testing-library';
import { isFeatureEnabled } from '@superset-ui/core';
import DatasourceEditor from '..';
import {
  createProps,
  setupDatasourceEditorMocks,
} from './DatasourceEditor.test.utils';

jest.mock('@superset-ui/core', () => ({
  ...jest.requireActual('@superset-ui/core'),
  isFeatureEnabled: jest.fn(),
}));

const routeProps = { history: {}, location: {}, match: {} };

beforeEach(() => {
  fetchMock.removeRoutes();
  setupDatasourceEditorMocks();
  fetchMock.get('glob:*/api/v1/dataset/7/execution_user_status', {
    execution_user: 'alice',
    token_present: true,
  });
  (isFeatureEnabled as jest.Mock).mockImplementation(
    flag => flag === 'DATASET_EXECUTION_USER',
  );
});

afterEach(() => {
  fetchMock.clearHistory().removeRoutes();
  (isFeatureEnabled as jest.Mock).mockReset();
});

test('shows the run-as setting to admins', async () => {
  const props = createProps();

  render(
    <DatasourceEditor
      {...props}
      {...routeProps}
      datasource={{ ...props.datasource, execution_user: 'alice' }}
    />,
    {
      useRedux: true,
      useRouter: true,
      initialState: {
        common: { currencies: [] },
        user: {
          username: 'admin',
          roles: { Admin: [] },
          permissions: {},
        },
      },
    },
  );

  userEvent.click(await screen.findByRole('tab', { name: 'Settings' }));

  expect(await screen.findByText('Run as')).toBeInTheDocument();
  expect(await screen.findByText('Specific user')).toBeInTheDocument();
});

test('lets a non-admin editor take over execution', async () => {
  const props = createProps();

  render(
    <DatasourceEditor
      {...props}
      {...routeProps}
      datasource={{ ...props.datasource, execution_user: 'alice' }}
    />,
    {
      useRedux: true,
      useRouter: true,
      initialState: {
        common: { currencies: [] },
        user: {
          username: 'bob',
          roles: { Gamma: [] },
          permissions: {},
        },
      },
    },
  );

  userEvent.click(await screen.findByRole('tab', { name: 'Settings' }));

  expect(
    await screen.findByText('Use my database credentials'),
  ).toBeInTheDocument();
  expect(
    await screen.findByText(/Currently runs as alice/),
  ).toBeInTheDocument();

  userEvent.click(screen.getByRole('switch'));

  expect(
    await screen.findByText(
      /Everyone who can query this dataset sees the data bob/,
    ),
  ).toBeInTheDocument();
});
