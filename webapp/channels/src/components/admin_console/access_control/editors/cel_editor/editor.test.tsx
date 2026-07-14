// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React from 'react';

import {searchUsersForExpression} from 'mattermost-redux/actions/access_control';
import {Client4} from 'mattermost-redux/client';

import {renderWithContext, screen, userEvent, waitFor} from 'tests/react_testing_utils';

import CELEditor from './editor';

jest.mock('monaco-editor', () => ({
    editor: {
        create: jest.fn(() => ({
            setValue: jest.fn(),
            getValue: jest.fn(() => ''),
            getModel: jest.fn(() => ({
                onDidChangeContent: jest.fn(() => ({dispose: jest.fn()})),
            })),
            onDidChangeCursorPosition: jest.fn(() => ({dispose: jest.fn()})),
            updateOptions: jest.fn(),
            dispose: jest.fn(),
        })),
        addKeybindingRule: jest.fn(),
    },
    KeyMod: {CtrlCmd: 2048},
    KeyCode: {KeyF: 36},
}));

jest.mock('./language_provider', () => ({
    MonacoLanguageProvider: () => null,
}));

jest.mock('mattermost-redux/actions/access_control', () => ({
    searchUsersForExpression: jest.fn(),
}));

describe('CELEditor', () => {
    const expression = 'user.attributes.department == "Engineering"';

    const baseProps = {
        value: expression,
        onChange: jest.fn(),
        userAttributes: [
            {attribute: 'department', values: ['Engineering']},
        ],
    };

    let checkExpressionSpy: jest.SpyInstance;

    beforeEach(() => {
        checkExpressionSpy = jest.spyOn(Client4, 'checkAccessControlExpression').mockResolvedValue([]);
        (searchUsersForExpression as jest.Mock).mockImplementation(() => () => Promise.resolve({data: {users: [], total: 0}}));
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    test('should use injected checkExpression and skip Client4', async () => {
        const checkExpression = jest.fn().mockResolvedValue([]);

        renderWithContext(
            <CELEditor
                {...baseProps}
                actions={{checkExpression}}
            />,
            {},
        );

        await waitFor(() => {
            expect(checkExpression).toHaveBeenCalledWith(expression);
        });
        expect(checkExpressionSpy).not.toHaveBeenCalled();
        expect(await screen.findByText('Valid')).toBeInTheDocument();
    });

    test('should fall back to Client4 when checkExpression is not injected', async () => {
        renderWithContext(
            <CELEditor
                {...baseProps}
                channelId='channel1'
                teamId='team1'
            />,
            {},
        );

        await waitFor(() => {
            expect(checkExpressionSpy).toHaveBeenCalledWith(expression, 'channel1', 'team1');
        });
        expect(await screen.findByText('Valid')).toBeInTheDocument();
    });

    test('should surface validation errors from injected checkExpression', async () => {
        const onValidate = jest.fn();
        const checkExpression = jest.fn().mockResolvedValue([
            {message: 'undeclared reference', line: 1, column: 0},
        ]);

        renderWithContext(
            <CELEditor
                {...baseProps}
                onValidate={onValidate}
                actions={{checkExpression}}
            />,
            {},
        );

        expect(await screen.findByText('undeclared reference @L1:1')).toBeInTheDocument();
        expect(onValidate).toHaveBeenCalledWith(false);
    });

    test('should use injected searchUsers for the test modal and skip the redux thunk', async () => {
        const checkExpression = jest.fn().mockResolvedValue([]);
        const mockSearch = jest.fn().mockResolvedValue({data: {users: [], total: 0}});

        renderWithContext(
            <CELEditor
                {...baseProps}
                actions={{checkExpression, searchUsers: mockSearch}}
            />,
            {},
        );

        await waitFor(() => {
            expect(screen.getByRole('button', {name: /test access rule/i})).not.toBeDisabled();
        });

        await userEvent.click(screen.getByRole('button', {name: /test access rule/i}));

        await waitFor(() => {
            expect(mockSearch).toHaveBeenCalledWith(expression, '', '', 50);
        });
        expect(searchUsersForExpression).not.toHaveBeenCalled();
    });

    test('should fall back to the redux thunk for the test modal when searchUsers is not injected', async () => {
        renderWithContext(
            <CELEditor
                {...baseProps}
                channelId='channel1'
                teamId='team1'
            />,
            {},
        );

        await waitFor(() => {
            expect(screen.getByRole('button', {name: /test access rule/i})).not.toBeDisabled();
        });

        await userEvent.click(screen.getByRole('button', {name: /test access rule/i}));

        await waitFor(() => {
            expect(searchUsersForExpression).toHaveBeenCalledWith(expression, '', '', 50, 'channel1', 'team1');
        });
        expect(screen.getByText('Access Rule Test Results')).toBeInTheDocument();
    });
});
