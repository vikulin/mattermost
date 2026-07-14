// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"errors"
	"net/http"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/mattermost/mattermost/server/v8/channels/app/properties"
	storemocks "github.com/mattermost/mattermost/server/v8/channels/store/storetest/mocks"
	"github.com/mattermost/mattermost/server/v8/einterfaces/mocks"
)

// ── Plugin-owned access control (PDP + PAP proxies for the plugin API) ──

const testAgentsPluginID = "mattermost-ai"

// enablePluginAccessControl licenses + configures the server so
// pluginAccessControlAvailable() is true (the enterprise service itself is
// injected per-test as a mock).
func enablePluginAccessControl(t *testing.T, th *TestHelper) {
	t.Helper()
	ok := th.App.Srv().SetLicense(model.NewTestLicenseSKU(model.LicenseShortSkuEnterpriseAdvanced))
	require.True(t, ok)
	th.App.UpdateConfig(func(cfg *model.Config) {
		*cfg.AccessControlSettings.EnableAttributeBasedAccessControl = true
	})
}

func validPluginPolicy(id string) *model.AccessControlPolicy {
	return &model.AccessControlPolicy{
		ID:      id,
		Type:    model.AccessControlPolicyTypePluginAgent,
		Name:    "Agent policy",
		Version: model.AccessControlPolicyVersionV0_5,
		Rules: []model.AccessControlPolicyRule{{
			Actions:    []string{model.AccessControlPolicyActionUse},
			Expression: `user.attributes.dept == "eng"`,
		}},
	}
}

// TestEvaluatePluginAccessRequest is the fail-closed contract matrix for the
// plugin PDP call: AppErrors only for caller programming errors, every
// operational condition an outcome, failures never mapping to allow/no_policy.
func TestEvaluatePluginAccessRequest(t *testing.T) {
	th := Setup(t).InitBasic(t)

	userID := th.BasicUser.Id
	resourceID := model.NewId()
	resourceType := model.AccessControlPolicyTypePluginAgent
	action := model.AccessControlPolicyActionUse

	t.Run("programming errors return AppErrors", func(t *testing.T) {
		enablePluginAccessControl(t, th)
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		tests := []struct {
			name           string
			pluginID       string
			userID         string
			resourceType   string
			resourceID     string
			action         string
			expectedStatus int
			expectedID     string
		}{
			{"unknown resource type", testAgentsPluginID, userID, "bogus.type", resourceID, action, http.StatusBadRequest, "app.access_control.plugin.unknown_resource_type.app_error"},
			{"foreign plugin", "other-plugin", userID, resourceType, resourceID, action, http.StatusForbidden, "app.access_control.plugin.resource_type_forbidden.app_error"},
			{"action not allowed", testAgentsPluginID, userID, resourceType, resourceID, model.AccessControlPolicyActionMembership, http.StatusBadRequest, "app.access_control.plugin.action_not_allowed.app_error"},
			{"invalid user id", testAgentsPluginID, "short", resourceType, resourceID, action, http.StatusBadRequest, "app.access_control.plugin.invalid_id.app_error"},
			{"invalid resource id", testAgentsPluginID, userID, resourceType, "short", action, http.StatusBadRequest, "app.access_control.plugin.invalid_id.app_error"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				decision, appErr := th.App.EvaluatePluginAccessRequest(th.Context, tc.pluginID, tc.userID, tc.resourceType, tc.resourceID, tc.action)
				require.NotNil(t, appErr)
				assert.Equal(t, tc.expectedStatus, appErr.StatusCode)
				assert.Equal(t, tc.expectedID, appErr.Id)
				assert.Nil(t, decision)
			})
		}
		mockACS.AssertNotCalled(t, "AccessEvaluation", mock.Anything, mock.Anything)
	})

	t.Run("service nil returns unavailable before enterprise call", func(t *testing.T) {
		enablePluginAccessControl(t, th)
		th.App.Srv().ch.AccessControl = nil

		decision, appErr := th.App.EvaluatePluginAccessRequest(th.Context, testAgentsPluginID, userID, resourceType, resourceID, action)
		require.Nil(t, appErr)
		require.Equal(t, model.AccessDecisionOutcomeUnavailable, decision.Outcome)
	})

	t.Run("insufficient license returns unavailable before enterprise call", func(t *testing.T) {
		enablePluginAccessControl(t, th)
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS
		ok := th.App.Srv().SetLicense(model.NewTestLicenseSKU(model.LicenseShortSkuProfessional))
		require.True(t, ok)

		decision, appErr := th.App.EvaluatePluginAccessRequest(th.Context, testAgentsPluginID, userID, resourceType, resourceID, action)
		require.Nil(t, appErr)
		require.Equal(t, model.AccessDecisionOutcomeUnavailable, decision.Outcome)
		mockACS.AssertNotCalled(t, "AccessEvaluation", mock.Anything, mock.Anything)
	})

	t.Run("disabled config flag returns unavailable before enterprise call", func(t *testing.T) {
		enablePluginAccessControl(t, th)
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS
		th.App.UpdateConfig(func(cfg *model.Config) {
			*cfg.AccessControlSettings.EnableAttributeBasedAccessControl = false
		})

		decision, appErr := th.App.EvaluatePluginAccessRequest(th.Context, testAgentsPluginID, userID, resourceType, resourceID, action)
		require.Nil(t, appErr)
		require.Equal(t, model.AccessDecisionOutcomeUnavailable, decision.Outcome)
		mockACS.AssertNotCalled(t, "AccessEvaluation", mock.Anything, mock.Anything)
	})

	t.Run("unknown user returns unavailable", func(t *testing.T) {
		enablePluginAccessControl(t, th)
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		decision, appErr := th.App.EvaluatePluginAccessRequest(th.Context, testAgentsPluginID, model.NewId(), resourceType, resourceID, action)
		require.Nil(t, appErr)
		require.Equal(t, model.AccessDecisionOutcomeUnavailable, decision.Outcome)
		mockACS.AssertNotCalled(t, "AccessEvaluation", mock.Anything, mock.Anything)
	})

	t.Run("subject build failure returns unavailable", func(t *testing.T) {
		enablePluginAccessControl(t, th)
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		// Force BuildAccessControlSubject to fail by breaking the CPA
		// property-group lookup (infra failure during subject build).
		mockGroupStore := &storemocks.PropertyGroupStore{}
		mockGroupStore.
			On("Get", model.AccessControlPropertyGroupName).
			Return((*model.PropertyGroup)(nil), errors.New("simulated store failure"))
		ps, err := properties.New(properties.ServiceConfig{
			PropertyGroupStore: mockGroupStore,
			PropertyFieldStore: &storemocks.PropertyFieldStore{},
			PropertyValueStore: &storemocks.PropertyValueStore{},
			CallerIDExtractor:  func(rctx request.CTX) string { return "" },
		})
		require.NoError(t, err)
		originalPS := th.App.Srv().propertyService
		th.App.Srv().propertyService = ps
		defer func() { th.App.Srv().propertyService = originalPS }()

		decision, appErr := th.App.EvaluatePluginAccessRequest(th.Context, testAgentsPluginID, userID, resourceType, resourceID, action)
		require.Nil(t, appErr)
		require.Equal(t, model.AccessDecisionOutcomeUnavailable, decision.Outcome)
		mockACS.AssertNotCalled(t, "AccessEvaluation", mock.Anything, mock.Anything)
	})

	t.Run("evaluator AppError returns unavailable", func(t *testing.T) {
		enablePluginAccessControl(t, th)
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS
		mockACS.On("AccessEvaluation", mock.Anything, mock.Anything).
			Return(model.AccessDecision{}, model.NewAppError("AccessEvaluation", "app.pdp.access_evaluation.app_error", nil, "boom", http.StatusInternalServerError)).Once()

		decision, appErr := th.App.EvaluatePluginAccessRequest(th.Context, testAgentsPluginID, userID, resourceType, resourceID, action)
		require.Nil(t, appErr)
		require.Equal(t, model.AccessDecisionOutcomeUnavailable, decision.Outcome)
		mockACS.AssertExpectations(t)
	})

	t.Run("evaluator outcomes pass through; empty outcome fails closed to unavailable", func(t *testing.T) {
		enablePluginAccessControl(t, th)

		tests := []struct {
			name     string
			decision model.AccessDecision
			expected model.AccessDecisionOutcome
		}{
			{"no_policy", model.AccessDecision{Decision: true, Outcome: model.AccessDecisionOutcomeNoPolicy}, model.AccessDecisionOutcomeNoPolicy},
			{"deny", model.AccessDecision{Decision: false, Outcome: model.AccessDecisionOutcomeDeny}, model.AccessDecisionOutcomeDeny},
			{"allow", model.AccessDecision{Decision: true, Outcome: model.AccessDecisionOutcomeAllow}, model.AccessDecisionOutcomeAllow},
			{"empty outcome (defensive)", model.AccessDecision{Decision: true}, model.AccessDecisionOutcomeUnavailable},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				mockACS := &mocks.AccessControlServiceInterface{}
				th.App.Srv().ch.AccessControl = mockACS
				mockACS.On("AccessEvaluation", mock.Anything, mock.MatchedBy(func(req model.AccessRequest) bool {
					return req.Resource.ID == resourceID &&
						req.Resource.Type == resourceType &&
						req.Action == action &&
						req.Subject.ID == userID &&
						req.Subject.RoleForScope(model.AccessControlSubjectScopeChannel) == ""
				})).Return(tc.decision, nil).Once()

				decision, appErr := th.App.EvaluatePluginAccessRequest(th.Context, testAgentsPluginID, userID, resourceType, resourceID, action)
				require.Nil(t, appErr)
				require.Equal(t, tc.expected, decision.Outcome)
				mockACS.AssertExpectations(t)
			})
		}
	})
}

func TestSavePluginAccessControlPolicy(t *testing.T) {
	th := Setup(t).InitBasic(t)
	actingUserID := th.BasicUser.Id

	notFoundErr := model.NewAppError("GetPolicy", "app.pap.get_policy.app_error", nil, "", http.StatusNotFound)

	t.Run("service nil returns 501", func(t *testing.T) {
		th.App.Srv().ch.AccessControl = nil
		_, appErr := th.App.SavePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, validPluginPolicy(model.NewId()))
		require.NotNil(t, appErr)
		assert.Equal(t, http.StatusNotImplemented, appErr.StatusCode)
	})

	t.Run("nil policy and missing ID rejected", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		_, appErr := th.App.SavePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, nil)
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.invalid_id.app_error", appErr.Id)

		p := validPluginPolicy("")
		_, appErr = th.App.SavePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, p)
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.invalid_id.app_error", appErr.Id)
		mockACS.AssertNotCalled(t, "SavePolicy", mock.Anything, mock.Anything)
	})

	t.Run("scope check failures", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		p := validPluginPolicy(model.NewId())
		p.Type = model.AccessControlPolicyTypeChannel
		_, appErr := th.App.SavePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, p)
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.unknown_resource_type.app_error", appErr.Id)

		_, appErr = th.App.SavePluginAccessControlPolicy(th.Context, "other-plugin", actingUserID, validPluginPolicy(model.NewId()))
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.resource_type_forbidden.app_error", appErr.Id)
		assert.Equal(t, http.StatusForbidden, appErr.StatusCode)
		mockACS.AssertNotCalled(t, "SavePolicy", mock.Anything, mock.Anything)
	})

	t.Run("acting user validation", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		_, appErr := th.App.SavePluginAccessControlPolicy(th.Context, testAgentsPluginID, "short", validPluginPolicy(model.NewId()))
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.invalid_acting_user.app_error", appErr.Id)

		_, appErr = th.App.SavePluginAccessControlPolicy(th.Context, testAgentsPluginID, model.NewId(), validPluginPolicy(model.NewId()))
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.invalid_acting_user.app_error", appErr.Id)
		mockACS.AssertNotCalled(t, "SavePolicy", mock.Anything, mock.Anything)
	})

	t.Run("create path forces v0.5 and Active, threads acting user session, passes rules verbatim", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		p := validPluginPolicy(model.NewId())
		p.Version = "v0.3" // caller-supplied version must be overridden
		p.Active = false
		expression := p.Rules[0].Expression

		mockACS.On("GetPolicy", mock.Anything, p.ID).Return(nil, notFoundErr).Once()
		mockACS.On("SavePolicy", mock.MatchedBy(func(c request.CTX) bool {
			return c.Session() != nil && c.Session().UserId == actingUserID
		}), mock.MatchedBy(func(saved *model.AccessControlPolicy) bool {
			return saved.Version == model.AccessControlPolicyVersionV0_5 &&
				saved.Active &&
				len(saved.Rules) == 1 &&
				len(saved.Rules[0].Actions) == 1 &&
				saved.Rules[0].Actions[0] == model.AccessControlPolicyActionUse &&
				saved.Rules[0].Expression == expression
		})).Return(p, nil).Once()

		saved, appErr := th.App.SavePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, p)
		require.Nil(t, appErr)
		require.NotNil(t, saved)
		mockACS.AssertExpectations(t)
	})

	t.Run("update path saves when stored type matches", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		p := validPluginPolicy(model.NewId())
		existing := validPluginPolicy(p.ID)
		mockACS.On("GetPolicy", mock.Anything, p.ID).Return(existing, nil).Once()
		mockACS.On("SavePolicy", mock.Anything, mock.Anything).Return(p, nil).Once()

		_, appErr := th.App.SavePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, p)
		require.Nil(t, appErr)
		mockACS.AssertExpectations(t)
	})

	t.Run("cross-type ID collision rejected", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		p := validPluginPolicy(model.NewId())
		channelPolicy := &model.AccessControlPolicy{ID: p.ID, Type: model.AccessControlPolicyTypeChannel}
		mockACS.On("GetPolicy", mock.Anything, p.ID).Return(channelPolicy, nil).Once()

		_, appErr := th.App.SavePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, p)
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.type_conflict.app_error", appErr.Id)
		mockACS.AssertNotCalled(t, "SavePolicy", mock.Anything, mock.Anything)
	})

	t.Run("validator failures surface and skip SavePolicy", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		p := validPluginPolicy(model.NewId())
		p.Imports = []string{model.NewId()}
		mockACS.On("GetPolicy", mock.Anything, p.ID).Return(nil, notFoundErr).Once()

		_, appErr := th.App.SavePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, p)
		require.NotNil(t, appErr)
		assert.Equal(t, "model.access_policy.is_valid.imports.app_error", appErr.Id)
		mockACS.AssertNotCalled(t, "SavePolicy", mock.Anything, mock.Anything)
	})

	t.Run("wildcard action rejected, never rewritten", func(t *testing.T) {
		// Risk pin: the legacy "*"→membership rewrite lives only in
		// CreateOrUpdateAccessControlPolicy; the plugin path must reject.
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		p := validPluginPolicy(model.NewId())
		p.Rules[0].Actions = []string{"*"}
		mockACS.On("GetPolicy", mock.Anything, p.ID).Return(nil, notFoundErr).Once()

		_, appErr := th.App.SavePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, p)
		require.NotNil(t, appErr)
		assert.Equal(t, "model.access_policy.is_valid.actions.app_error", appErr.Id)
		mockACS.AssertNotCalled(t, "SavePolicy", mock.Anything, mock.Anything)
	})

	t.Run("existence probe infra error propagates", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		p := validPluginPolicy(model.NewId())
		infraErr := model.NewAppError("GetPolicy", "app.pap.get_policy.app_error", nil, "", http.StatusInternalServerError)
		mockACS.On("GetPolicy", mock.Anything, p.ID).Return(nil, infraErr).Once()

		_, appErr := th.App.SavePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, p)
		require.NotNil(t, appErr)
		assert.Equal(t, http.StatusInternalServerError, appErr.StatusCode)
		mockACS.AssertNotCalled(t, "SavePolicy", mock.Anything, mock.Anything)
	})
}

func TestGetPluginAccessControlPolicy(t *testing.T) {
	th := Setup(t).InitBasic(t)

	t.Run("service nil returns 501", func(t *testing.T) {
		th.App.Srv().ch.AccessControl = nil
		_, appErr := th.App.GetPluginAccessControlPolicy(th.Context, testAgentsPluginID, model.NewId())
		require.NotNil(t, appErr)
		assert.Equal(t, http.StatusNotImplemented, appErr.StatusCode)
	})

	t.Run("invalid id returns 400", func(t *testing.T) {
		th.App.Srv().ch.AccessControl = &mocks.AccessControlServiceInterface{}
		_, appErr := th.App.GetPluginAccessControlPolicy(th.Context, testAgentsPluginID, "short")
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.invalid_id.app_error", appErr.Id)
	})

	t.Run("found and owned returns policy", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		p := validPluginPolicy(model.NewId())
		mockACS.On("GetPolicy", mock.Anything, p.ID).Return(p, nil).Once()

		policy, appErr := th.App.GetPluginAccessControlPolicy(th.Context, testAgentsPluginID, p.ID)
		require.Nil(t, appErr)
		require.Equal(t, p, policy)
		mockACS.AssertExpectations(t)
	})

	t.Run("enterprise 404 propagates", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		id := model.NewId()
		mockACS.On("GetPolicy", mock.Anything, id).
			Return(nil, model.NewAppError("GetPolicy", "app.pap.get_policy.app_error", nil, "", http.StatusNotFound)).Once()

		_, appErr := th.App.GetPluginAccessControlPolicy(th.Context, testAgentsPluginID, id)
		require.NotNil(t, appErr)
		assert.Equal(t, http.StatusNotFound, appErr.StatusCode)
	})

	t.Run("non-plugin stored type fails closed with 404", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		id := model.NewId()
		mockACS.On("GetPolicy", mock.Anything, id).
			Return(&model.AccessControlPolicy{ID: id, Type: model.AccessControlPolicyTypeChannel}, nil).Once()

		_, appErr := th.App.GetPluginAccessControlPolicy(th.Context, testAgentsPluginID, id)
		require.NotNil(t, appErr)
		assert.Equal(t, http.StatusNotFound, appErr.StatusCode)
		assert.Equal(t, "app.access_control.plugin.policy_not_found.app_error", appErr.Id)
	})

	t.Run("foreign-owned stored type fails closed with 404", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		p := validPluginPolicy(model.NewId())
		mockACS.On("GetPolicy", mock.Anything, p.ID).Return(p, nil).Once()

		_, appErr := th.App.GetPluginAccessControlPolicy(th.Context, "other-plugin", p.ID)
		require.NotNil(t, appErr)
		assert.Equal(t, http.StatusNotFound, appErr.StatusCode)
		assert.Equal(t, "app.access_control.plugin.policy_not_found.app_error", appErr.Id)
	})
}

func TestDeletePluginAccessControlPolicy(t *testing.T) {
	th := Setup(t).InitBasic(t)
	actingUserID := th.BasicUser.Id
	resourceType := model.AccessControlPolicyTypePluginAgent

	t.Run("service nil returns 501", func(t *testing.T) {
		th.App.Srv().ch.AccessControl = nil
		appErr := th.App.DeletePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, resourceType, model.NewId())
		require.NotNil(t, appErr)
		assert.Equal(t, http.StatusNotImplemented, appErr.StatusCode)
	})

	t.Run("programming errors", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		appErr := th.App.DeletePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, "bogus.type", model.NewId())
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.unknown_resource_type.app_error", appErr.Id)

		appErr = th.App.DeletePluginAccessControlPolicy(th.Context, "other-plugin", actingUserID, resourceType, model.NewId())
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.resource_type_forbidden.app_error", appErr.Id)

		appErr = th.App.DeletePluginAccessControlPolicy(th.Context, testAgentsPluginID, "short", resourceType, model.NewId())
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.invalid_acting_user.app_error", appErr.Id)

		appErr = th.App.DeletePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, resourceType, "short")
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.invalid_id.app_error", appErr.Id)

		mockACS.AssertNotCalled(t, "DeletePolicy", mock.Anything, mock.Anything)
	})

	t.Run("missing policy propagates 404", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		id := model.NewId()
		mockACS.On("GetPolicy", mock.Anything, id).
			Return(nil, model.NewAppError("GetPolicy", "app.pap.get_policy.app_error", nil, "", http.StatusNotFound)).Once()

		appErr := th.App.DeletePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, resourceType, id)
		require.NotNil(t, appErr)
		assert.Equal(t, http.StatusNotFound, appErr.StatusCode)
		mockACS.AssertNotCalled(t, "DeletePolicy", mock.Anything, mock.Anything)
	})

	t.Run("stored type mismatch fails closed with 404", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		id := model.NewId()
		stored := validPluginPolicy(id)
		stored.Type = model.AccessControlPolicyTypePluginService
		mockACS.On("GetPolicy", mock.Anything, id).Return(stored, nil).Once()

		appErr := th.App.DeletePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, resourceType, id)
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.policy_not_found.app_error", appErr.Id)
		mockACS.AssertNotCalled(t, "DeletePolicy", mock.Anything, mock.Anything)
	})

	t.Run("non-plugin stored type fails closed with 404", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		id := model.NewId()
		mockACS.On("GetPolicy", mock.Anything, id).
			Return(&model.AccessControlPolicy{ID: id, Type: model.AccessControlPolicyTypeChannel}, nil).Once()

		appErr := th.App.DeletePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, model.AccessControlPolicyTypePluginAgent, id)
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.policy_not_found.app_error", appErr.Id)
		mockACS.AssertNotCalled(t, "DeletePolicy", mock.Anything, mock.Anything)
	})

	t.Run("happy path deletes", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		id := model.NewId()
		mockACS.On("GetPolicy", mock.Anything, id).Return(validPluginPolicy(id), nil).Once()
		mockACS.On("DeletePolicy", mock.Anything, id).Return(nil).Once()

		appErr := th.App.DeletePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, resourceType, id)
		require.Nil(t, appErr)
		mockACS.AssertExpectations(t)
	})
}

func TestPluginAccessControlCELProxies(t *testing.T) {
	th := Setup(t).InitBasic(t)
	actingUserID := th.BasicUser.Id
	resourceType := model.AccessControlPolicyTypePluginAgent
	expression := `user.attributes.dept == "eng"`

	t.Run("scope check enforced on check/test/visual_ast", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		_, appErr := th.App.CheckPluginAccessControlExpression(th.Context, "other-plugin", actingUserID, resourceType, expression)
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.resource_type_forbidden.app_error", appErr.Id)

		_, appErr = th.App.QueryUsersForPluginAccessControlExpression(th.Context, testAgentsPluginID, actingUserID, "bogus.type", expression, "", "", 10)
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.unknown_resource_type.app_error", appErr.Id)

		_, appErr = th.App.GetPluginAccessControlVisualAST(th.Context, "other-plugin", actingUserID, resourceType, expression)
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.resource_type_forbidden.app_error", appErr.Id)

		mockACS.AssertNotCalled(t, "CheckExpression", mock.Anything, mock.Anything)
		mockACS.AssertNotCalled(t, "QueryUsersForExpression", mock.Anything, mock.Anything, mock.Anything)
		mockACS.AssertNotCalled(t, "ExpressionToVisualAST", mock.Anything, mock.Anything)
	})

	t.Run("check expression threads acting user session", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS
		mockACS.On("CheckExpression", mock.MatchedBy(func(c request.CTX) bool {
			return c.Session() != nil && c.Session().UserId == actingUserID
		}), expression).Return([]model.CELExpressionError{}, nil).Once()

		errs, appErr := th.App.CheckPluginAccessControlExpression(th.Context, testAgentsPluginID, actingUserID, resourceType, expression)
		require.Nil(t, appErr)
		require.Empty(t, errs)
		mockACS.AssertExpectations(t)
	})

	t.Run("query users wraps response and clamps limit", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		cursorID := model.NewId()
		users := []*model.User{th.BasicUser}
		mockACS.On("QueryUsersForExpression", mock.MatchedBy(func(c request.CTX) bool {
			return c.Session() != nil && c.Session().UserId == actingUserID
		}), expression, mock.MatchedBy(func(opts model.SubjectSearchOptions) bool {
			return opts.Term == "ali" &&
				opts.Limit == pluginAccessControlQueryLimitMax &&
				opts.Cursor.TargetID == cursorID
		})).Return(users, int64(1), nil).Once()

		resp, appErr := th.App.QueryUsersForPluginAccessControlExpression(th.Context, testAgentsPluginID, actingUserID, resourceType, expression, "ali", cursorID, 10000)
		require.Nil(t, appErr)
		require.Equal(t, users, resp.Users)
		require.Equal(t, int64(1), resp.Total)
		mockACS.AssertExpectations(t)

		mockACS.On("QueryUsersForExpression", mock.Anything, expression, mock.MatchedBy(func(opts model.SubjectSearchOptions) bool {
			return opts.Limit == pluginAccessControlQueryLimitDefault
		})).Return(users, int64(1), nil).Once()
		_, appErr = th.App.QueryUsersForPluginAccessControlExpression(th.Context, testAgentsPluginID, actingUserID, resourceType, expression, "", "", 0)
		require.Nil(t, appErr)
		mockACS.AssertExpectations(t)
	})

	t.Run("autocomplete requires only a valid acting user", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		_, appErr := th.App.GetPluginAccessControlFieldsAutocomplete(th.Context, testAgentsPluginID, model.NewId(), "", 10)
		require.NotNil(t, appErr)
		assert.Equal(t, "app.access_control.plugin.invalid_acting_user.app_error", appErr.Id)

		fields, appErr := th.App.GetPluginAccessControlFieldsAutocomplete(th.Context, testAgentsPluginID, actingUserID, "", 10)
		require.Nil(t, appErr)
		require.NotEmpty(t, fields, "native attribute fields expected on the first page")
	})

	t.Run("autocomplete gates on missing service", func(t *testing.T) {
		th.App.Srv().ch.AccessControl = nil
		_, appErr := th.App.GetPluginAccessControlFieldsAutocomplete(th.Context, testAgentsPluginID, actingUserID, "", 10)
		require.NotNil(t, appErr)
		assert.Equal(t, http.StatusNotImplemented, appErr.StatusCode)
	})

	t.Run("visual AST proxies to the service", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		visual := &model.VisualExpression{}
		mockACS.On("ExpressionToVisualAST", mock.Anything, expression).Return(visual, nil).Once()

		ast, appErr := th.App.GetPluginAccessControlVisualAST(th.Context, testAgentsPluginID, actingUserID, resourceType, expression)
		require.Nil(t, appErr)
		require.Equal(t, visual, ast)
		mockACS.AssertExpectations(t)
	})
}
