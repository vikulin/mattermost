// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import React from 'react';

import ManageTeamsDropdown from 'components/admin_console/manage_teams_modal/manage_teams_dropdown';

import {renderWithContext, screen, userEvent, waitFor} from 'tests/react_testing_utils';
import {TestHelper} from 'utils/test_helper';

describe('ManageTeamsDropdown', () => {
    const baseProps = {
        team: TestHelper.getTeamMock({id: 'teamid', group_constrained: false}),
        user: TestHelper.getUserMock({
            id: 'currentUserId',
            last_picture_update: 1234,
            email: 'currentUser@test.com',
            roles: 'system_user',
            username: 'currentUsername',
        }),
        teamMember: TestHelper.getTeamMembershipMock({
            team_id: 'teamid',
            scheme_user: true,
            scheme_guest: false,
            scheme_admin: false,
        }),
        index: 0,
        totalTeams: 1,
        onError: jest.fn(),
        onMemberChange: jest.fn(),
        updateTeamMemberSchemeRoles: jest.fn().mockResolvedValue({}),
        handleRemoveUserFromTeam: jest.fn(),
    };

    test('shows the "Team Member" role for a plain member and the member actions when opened', async () => {
        renderWithContext(<ManageTeamsDropdown {...baseProps}/>);

        await userEvent.click(screen.getByRole('button', {name: /Team Member/i}));

        expect(screen.getByRole('menuitem', {name: 'Make Team Admin'})).toBeInTheDocument();
        expect(screen.getByRole('menuitem', {name: 'Remove from Team'})).toBeInTheDocument();
        expect(screen.queryByRole('menuitem', {name: 'Make Team Member'})).not.toBeInTheDocument();
    });

    test('shows the "Team Admin" role and the demote action for a team admin', async () => {
        const props = {
            ...baseProps,
            teamMember: {...baseProps.teamMember, scheme_admin: true},
        };

        renderWithContext(<ManageTeamsDropdown {...props}/>);

        await userEvent.click(screen.getByRole('button', {name: /Team Admin/i}));

        expect(screen.getByRole('menuitem', {name: 'Make Team Member'})).toBeInTheDocument();
        expect(screen.getByRole('menuitem', {name: 'Remove from Team'})).toBeInTheDocument();
        expect(screen.queryByRole('menuitem', {name: 'Make Team Admin'})).not.toBeInTheDocument();
    });

    test('shows the "Guest" role and no promotion action for a guest', async () => {
        const props = {
            ...baseProps,
            user: {...baseProps.user, roles: 'system_guest'},
        };

        renderWithContext(<ManageTeamsDropdown {...props}/>);

        await userEvent.click(screen.getByRole('button', {name: /Guest/i}));

        expect(screen.getByRole('menuitem', {name: 'Remove from Team'})).toBeInTheDocument();
        expect(screen.queryByRole('menuitem', {name: 'Make Team Admin'})).not.toBeInTheDocument();
        expect(screen.queryByRole('menuitem', {name: 'Make Team Member'})).not.toBeInTheDocument();
    });

    test('hides "Remove from Team" for a group constrained team', async () => {
        const props = {
            ...baseProps,
            team: TestHelper.getTeamMock({id: 'teamid', group_constrained: true}),
        };

        renderWithContext(<ManageTeamsDropdown {...props}/>);

        await userEvent.click(screen.getByRole('button', {name: /Team Member/i}));

        expect(screen.getByRole('menuitem', {name: 'Make Team Admin'})).toBeInTheDocument();
        expect(screen.queryByRole('menuitem', {name: 'Remove from Team'})).not.toBeInTheDocument();
    });

    test('promotes the member to team admin and reports the change', async () => {
        renderWithContext(<ManageTeamsDropdown {...baseProps}/>);

        await userEvent.click(screen.getByRole('button', {name: /Team Member/i}));
        await userEvent.click(screen.getByRole('menuitem', {name: 'Make Team Admin'}));

        await waitFor(() => {
            expect(baseProps.updateTeamMemberSchemeRoles).toHaveBeenCalledWith('teamid', 'currentUserId', true, true);
        });
        expect(baseProps.onMemberChange).toHaveBeenCalledWith('teamid');
    });

    test('removes the user from the team', async () => {
        renderWithContext(<ManageTeamsDropdown {...baseProps}/>);

        await userEvent.click(screen.getByRole('button', {name: /Team Member/i}));
        await userEvent.click(screen.getByRole('menuitem', {name: 'Remove from Team'}));

        await waitFor(() => {
            expect(baseProps.handleRemoveUserFromTeam).toHaveBeenCalledWith('teamid');
        });
    });

    test('surfaces an error when the promotion request fails', async () => {
        const onError = jest.fn();
        const props = {
            ...baseProps,
            onError,
            onMemberChange: jest.fn(),
            updateTeamMemberSchemeRoles: jest.fn().mockResolvedValue({error: {message: 'boom'}}),
        };

        renderWithContext(<ManageTeamsDropdown {...props}/>);

        await userEvent.click(screen.getByRole('button', {name: /Team Member/i}));
        await userEvent.click(screen.getByRole('menuitem', {name: 'Make Team Admin'}));

        await waitFor(() => {
            expect(onError).toHaveBeenCalled();
        });
        expect(props.onMemberChange).not.toHaveBeenCalled();
    });
});
