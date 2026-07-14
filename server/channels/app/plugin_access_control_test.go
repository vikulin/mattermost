// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/mattermost/mattermost/server/v8/channels/app/properties"
	storemocks "github.com/mattermost/mattermost/server/v8/channels/store/storetest/mocks"
	"github.com/mattermost/mattermost/server/v8/config"
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

	savePolicyToStore := func(t *testing.T, p *model.AccessControlPolicy) {
		t.Helper()
		_, err := th.App.Srv().Store().AccessControlPolicy().Save(th.Context, p)
		require.NoError(t, err)
		t.Cleanup(func() { _ = th.App.Srv().Store().AccessControlPolicy().Delete(th.Context, p.ID) })
	}

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

	t.Run("found and owned returns the normalized policy", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		p := validPluginPolicy(model.NewId())
		p.Active = true
		savePolicyToStore(t, p)

		normalized := validPluginPolicy(p.ID)
		mockACS.On("GetPolicy", mock.Anything, p.ID).Return(normalized, nil).Once()

		policy, appErr := th.App.GetPluginAccessControlPolicy(th.Context, testAgentsPluginID, p.ID)
		require.Nil(t, appErr)
		require.Equal(t, normalized, policy)
		mockACS.AssertExpectations(t)
	})

	t.Run("absent, foreign-type, and foreign-owner return the same byte-identical 404 without touching normalization", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		// Absent: no stored row at all.
		_, absentErr := th.App.GetPluginAccessControlPolicy(th.Context, testAgentsPluginID, model.NewId())

		// Foreign type: a stored channel policy under the requested ID.
		channelPolicy := &model.AccessControlPolicy{
			ID:       model.NewId(),
			Name:     "channel-policy",
			Type:     model.AccessControlPolicyTypeChannel,
			Active:   true,
			Revision: 1,
			Version:  model.AccessControlPolicyVersionV0_1,
			Rules:    []model.AccessControlPolicyRule{{Actions: []string{"*"}, Expression: "true"}},
		}
		savePolicyToStore(t, channelPolicy)
		_, foreignTypeErr := th.App.GetPluginAccessControlPolicy(th.Context, testAgentsPluginID, channelPolicy.ID)

		// Foreign owner: a stored plugin policy requested by a non-owner plugin.
		owned := validPluginPolicy(model.NewId())
		owned.Active = true
		savePolicyToStore(t, owned)
		_, foreignOwnerErr := th.App.GetPluginAccessControlPolicy(th.Context, "other-plugin", owned.ID)

		for _, appErr := range []*model.AppError{absentErr, foreignTypeErr, foreignOwnerErr} {
			require.NotNil(t, appErr)
			assert.Equal(t, http.StatusNotFound, appErr.StatusCode)
			assert.Equal(t, "app.access_control.plugin.policy_not_found.app_error", appErr.Id)
		}
		// Indistinguishable: identical error content across all three causes.
		assert.Equal(t, absentErr.Error(), foreignTypeErr.Error())
		assert.Equal(t, absentErr.Error(), foreignOwnerErr.Error())

		// Normalization never ran — no existence signal can leak through it.
		mockACS.AssertNotCalled(t, "GetPolicy", mock.Anything, mock.Anything)
	})

	t.Run("normalization failure after ownership passes surfaces as its own error", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		p := validPluginPolicy(model.NewId())
		p.Active = true
		savePolicyToStore(t, p)

		mockACS.On("GetPolicy", mock.Anything, p.ID).
			Return(nil, model.NewAppError("GetPolicy", "app.pap.get_policy.app_error", nil, "normalize failed", http.StatusInternalServerError)).Once()

		_, appErr := th.App.GetPluginAccessControlPolicy(th.Context, testAgentsPluginID, p.ID)
		require.NotNil(t, appErr)
		assert.Equal(t, http.StatusInternalServerError, appErr.StatusCode)
		mockACS.AssertExpectations(t)
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

		mockACS.AssertNotCalled(t, "DeletePolicyOfType", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("absent and stored-type mismatch return the same byte-identical 404", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		// The enterprise 404s deliberately carry different details (absent vs
		// guarded-delete miss); the app layer must collapse both.
		absentID := model.NewId()
		mismatchID := model.NewId()
		mockACS.On("DeletePolicyOfType", mock.Anything, absentID, resourceType).
			Return(model.NewAppError("DeletePolicyOfType", "app.pap.delete_policy.app_error", nil, "resource: AccessControlPolicy id: "+absentID, http.StatusNotFound)).Once()
		mockACS.On("DeletePolicyOfType", mock.Anything, mismatchID, resourceType).
			Return(model.NewAppError("DeletePolicyOfType", "app.pap.delete_policy.app_error", nil, "type mismatch", http.StatusNotFound)).Once()

		absentErr := th.App.DeletePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, resourceType, absentID)
		mismatchErr := th.App.DeletePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, resourceType, mismatchID)

		require.NotNil(t, absentErr)
		require.NotNil(t, mismatchErr)
		assert.Equal(t, "app.access_control.plugin.policy_not_found.app_error", absentErr.Id)
		assert.Equal(t, absentErr.Error(), mismatchErr.Error())
		mockACS.AssertExpectations(t)
	})

	t.Run("happy path deletes atomically with the expected type", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		id := model.NewId()
		mockACS.On("DeletePolicyOfType", mock.Anything, id, resourceType).Return(nil).Once()

		appErr := th.App.DeletePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, resourceType, id)
		require.Nil(t, appErr)
		mockACS.AssertExpectations(t)
		// No read-then-delete: the type guard lives inside the atomic delete.
		mockACS.AssertNotCalled(t, "GetPolicy", mock.Anything, mock.Anything)
		mockACS.AssertNotCalled(t, "DeletePolicy", mock.Anything, mock.Anything)
	})

	t.Run("infra error propagates", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		id := model.NewId()
		mockACS.On("DeletePolicyOfType", mock.Anything, id, resourceType).
			Return(model.NewAppError("DeletePolicyOfType", "app.pap.delete_policy.app_error", nil, "db down", http.StatusInternalServerError)).Once()

		appErr := th.App.DeletePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, resourceType, id)
		require.NotNil(t, appErr)
		assert.Equal(t, http.StatusInternalServerError, appErr.StatusCode)
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

// pluginAuditCapture routes the test server's audit logger to a temp file so
// tests can assert that plugin PAP methods emit audit records for every
// attempt, not just successful ones.
type pluginAuditCapture struct {
	t    *testing.T
	th   *TestHelper
	path string
}

func startPluginAuditCapture(t *testing.T, th *TestHelper) *pluginAuditCapture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	cfg, err := config.MloggerConfigFromAuditConfig(model.ExperimentalAuditSettings{
		FileEnabled: model.NewPointer(true),
		FileName:    model.NewPointer(path),
	}, nil)
	require.NoError(t, err)
	require.NoError(t, th.App.Srv().Audit.Configure(cfg))
	return &pluginAuditCapture{t: t, th: th, path: path}
}

// recordsFor returns all audit records logged so far for the given event.
func (c *pluginAuditCapture) recordsFor(event string) []map[string]any {
	c.t.Helper()
	require.NoError(c.t, c.th.App.Srv().Audit.Flush())
	data, err := os.ReadFile(c.path)
	if errors.Is(err, os.ErrNotExist) {
		// The file target creates the log lazily on first write.
		return nil
	}
	require.NoError(c.t, err)

	var out []map[string]any
	for line := range bytesLines(data) {
		var rec map[string]any
		require.NoError(c.t, json.Unmarshal(line, &rec))
		if rec[model.AuditKeyEventName] == event {
			out = append(out, rec)
		}
	}
	return out
}

// bytesLines yields non-empty newline-separated chunks of data.
func bytesLines(data []byte) func(func([]byte) bool) {
	return func(yield func([]byte) bool) {
		start := 0
		for i := range data {
			if data[i] != '\n' {
				continue
			}
			if i > start && !yield(data[start:i]) {
				return
			}
			start = i + 1
		}
		if start < len(data) {
			yield(data[start:])
		}
	}
}

func auditParam(t *testing.T, rec map[string]any, key string) any {
	t.Helper()
	event, ok := rec[model.AuditKeyEvent].(map[string]any)
	require.True(t, ok, "audit record has no event data")
	params, ok := event["parameters"].(map[string]any)
	require.True(t, ok, "audit record has no event parameters")
	return params[key]
}

// TestPluginAccessControlAudit pins that Save/Delete audit EVERY attempt —
// including precondition failures before the enterprise service is touched —
// and that the records carry the actor/plugin/type/operation parameters and
// the correct success/fail status.
func TestPluginAccessControlAudit(t *testing.T) {
	th := Setup(t).InitBasic(t)
	capture := startPluginAuditCapture(t, th)

	actingUserID := th.BasicUser.Id
	resourceType := model.AccessControlPolicyTypePluginAgent

	// assertNextRecord runs fn and asserts exactly one new audit record for
	// event was emitted, returning it.
	assertNextRecord := func(t *testing.T, event, wantStatus string, fn func()) map[string]any {
		t.Helper()
		before := len(capture.recordsFor(event))
		fn()
		records := capture.recordsFor(event)
		require.Len(t, records, before+1, "expected exactly one new %s audit record", event)
		rec := records[len(records)-1]
		assert.Equal(t, wantStatus, rec[model.AuditKeyStatus])
		return rec
	}

	t.Run("save: service unavailable still audits as fail", func(t *testing.T) {
		th.App.Srv().ch.AccessControl = nil
		rec := assertNextRecord(t, model.AuditEventSavePluginAccessControlPolicy, model.AuditStatusFail, func() {
			_, appErr := th.App.SavePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, validPluginPolicy(model.NewId()))
			require.NotNil(t, appErr)
		})
		assert.Equal(t, testAgentsPluginID, auditParam(t, rec, "plugin_id"))
		assert.Equal(t, actingUserID, auditParam(t, rec, "actor"))
		assert.Equal(t, resourceType, auditParam(t, rec, "resource_type"))
	})

	t.Run("save: invalid (nil) policy audits as fail", func(t *testing.T) {
		th.App.Srv().ch.AccessControl = &mocks.AccessControlServiceInterface{}
		rec := assertNextRecord(t, model.AuditEventSavePluginAccessControlPolicy, model.AuditStatusFail, func() {
			_, appErr := th.App.SavePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, nil)
			require.NotNil(t, appErr)
		})
		assert.Equal(t, testAgentsPluginID, auditParam(t, rec, "plugin_id"))
	})

	t.Run("save: ownership failure audits as fail", func(t *testing.T) {
		th.App.Srv().ch.AccessControl = &mocks.AccessControlServiceInterface{}
		rec := assertNextRecord(t, model.AuditEventSavePluginAccessControlPolicy, model.AuditStatusFail, func() {
			_, appErr := th.App.SavePluginAccessControlPolicy(th.Context, "other-plugin", actingUserID, validPluginPolicy(model.NewId()))
			require.NotNil(t, appErr)
		})
		assert.Equal(t, "other-plugin", auditParam(t, rec, "plugin_id"))
	})

	t.Run("save: success audits as success with operation", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		p := validPluginPolicy(model.NewId())
		mockACS.On("GetPolicy", mock.Anything, p.ID).
			Return(nil, model.NewAppError("GetPolicy", "app.pap.get_policy.app_error", nil, "", http.StatusNotFound)).Once()
		mockACS.On("SavePolicy", mock.Anything, mock.Anything).Return(p, nil).Once()

		rec := assertNextRecord(t, model.AuditEventSavePluginAccessControlPolicy, model.AuditStatusSuccess, func() {
			_, appErr := th.App.SavePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, p)
			require.Nil(t, appErr)
		})
		assert.Equal(t, "create", auditParam(t, rec, "operation"))
		mockACS.AssertExpectations(t)
	})

	t.Run("delete: service unavailable still audits as fail", func(t *testing.T) {
		th.App.Srv().ch.AccessControl = nil
		rec := assertNextRecord(t, model.AuditEventDeletePluginAccessControlPolicy, model.AuditStatusFail, func() {
			appErr := th.App.DeletePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, resourceType, model.NewId())
			require.NotNil(t, appErr)
		})
		assert.Equal(t, "delete", auditParam(t, rec, "operation"))
		assert.Equal(t, actingUserID, auditParam(t, rec, "actor"))
	})

	t.Run("delete: malformed policy ID audits as fail", func(t *testing.T) {
		th.App.Srv().ch.AccessControl = &mocks.AccessControlServiceInterface{}
		rec := assertNextRecord(t, model.AuditEventDeletePluginAccessControlPolicy, model.AuditStatusFail, func() {
			appErr := th.App.DeletePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, resourceType, "short")
			require.NotNil(t, appErr)
		})
		assert.Equal(t, "short", auditParam(t, rec, "policy_id"))
	})

	t.Run("delete: ownership failure audits as fail", func(t *testing.T) {
		th.App.Srv().ch.AccessControl = &mocks.AccessControlServiceInterface{}
		rec := assertNextRecord(t, model.AuditEventDeletePluginAccessControlPolicy, model.AuditStatusFail, func() {
			appErr := th.App.DeletePluginAccessControlPolicy(th.Context, "other-plugin", actingUserID, resourceType, model.NewId())
			require.NotNil(t, appErr)
		})
		assert.Equal(t, "other-plugin", auditParam(t, rec, "plugin_id"))
	})

	t.Run("delete: success audits as success", func(t *testing.T) {
		mockACS := &mocks.AccessControlServiceInterface{}
		th.App.Srv().ch.AccessControl = mockACS

		id := model.NewId()
		mockACS.On("DeletePolicyOfType", mock.Anything, id, resourceType).Return(nil).Once()

		rec := assertNextRecord(t, model.AuditEventDeletePluginAccessControlPolicy, model.AuditStatusSuccess, func() {
			appErr := th.App.DeletePluginAccessControlPolicy(th.Context, testAgentsPluginID, actingUserID, resourceType, id)
			require.Nil(t, appErr)
		})
		assert.Equal(t, id, auditParam(t, rec, "policy_id"))
		mockACS.AssertExpectations(t)
	})
}
