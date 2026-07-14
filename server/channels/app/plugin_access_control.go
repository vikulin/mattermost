// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"net/http"
	"strings"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
)

// ── Plugin-owned access control (PDP + PAP proxies for the plugin API) ──
//
// Plugin-registered resource types (model.PluginAccessControlResourceTypeFor)
// are managed exclusively through these methods. Every method is scoped to the
// calling plugin: the requested (or stored) policy type must be owned by
// pluginID or the call fails closed.

// pluginAccessControlQueryLimitDefault / Max bound plugin-supplied paging for
// the users-query proxy so an unbounded limit can't become an unbounded user
// query. Max mirrors the api4 autocomplete handler's cap.
const (
	pluginAccessControlQueryLimitDefault = 50
	pluginAccessControlQueryLimitMax     = 100
)

// pluginAccessControlScopeCheck resolves the registry entry for resourceType
// and verifies ownership by pluginID. Returns (entry, nil) or a 400/403 AppError.
func (a *App) pluginAccessControlScopeCheck(where, pluginID, resourceType string) (model.PluginAccessControlResourceType, *model.AppError) {
	rt, ok := model.PluginAccessControlResourceTypeFor(resourceType)
	if !ok {
		return model.PluginAccessControlResourceType{}, model.NewAppError(where, "app.access_control.plugin.unknown_resource_type.app_error", nil, resourceType, http.StatusBadRequest)
	}
	if !rt.IsOwnedBy(pluginID) {
		return model.PluginAccessControlResourceType{}, model.NewAppError(where, "app.access_control.plugin.resource_type_forbidden.app_error", nil, "plugin_id="+pluginID, http.StatusForbidden)
	}
	return rt, nil
}

// pluginAccessControlAvailable reports whether the enterprise ABAC service can
// possibly answer: service registered AND Enterprise Advanced license AND
// config flag on. Checked BEFORE calling enterprise so its readiness AppErrors
// never leak into plugin decision calls.
func (a *App) pluginAccessControlAvailable() bool {
	return a.Srv().ch.AccessControl != nil &&
		model.MinimumEnterpriseAdvancedLicense(a.License()) &&
		*a.Config().AccessControlSettings.EnableAttributeBasedAccessControl
}

// validatePluginActingUser validates actingUserID is a well-formed ID of an
// existing user. 400 on failure (trusted call — the plugin is the permission
// gate, core does not re-run permission checks).
func (a *App) validatePluginActingUser(where, actingUserID string) *model.AppError {
	if !model.IsValidId(actingUserID) {
		return model.NewAppError(where, "app.access_control.plugin.invalid_acting_user.app_error", nil, "", http.StatusBadRequest)
	}
	if _, appErr := a.GetUser(actingUserID); appErr != nil {
		return model.NewAppError(where, "app.access_control.plugin.invalid_acting_user.app_error", nil, "", http.StatusBadRequest).Wrap(appErr)
	}
	return nil
}

// EvaluatePluginAccessRequest evaluates whether userID may perform action on
// the plugin-registered resource (resourceType, resourceID). AppErrors are
// returned only for caller programming errors (unknown/foreign type, bad
// action, malformed IDs); every operational condition is an outcome:
// unavailable (service off / unlicensed / disabled / infra failure before
// policy resolution), no_policy, deny, or allow. Failures never map to allow
// or no_policy.
func (a *App) EvaluatePluginAccessRequest(rctx request.CTX, pluginID, userID, resourceType, resourceID, action string) (*model.PluginAccessControlDecision, *model.AppError) {
	rt, appErr := a.pluginAccessControlScopeCheck("EvaluatePluginAccessRequest", pluginID, resourceType)
	if appErr != nil {
		return nil, appErr
	}
	if !rt.IsActionAllowed(action) {
		return nil, model.NewAppError("EvaluatePluginAccessRequest", "app.access_control.plugin.action_not_allowed.app_error", nil, "action="+action, http.StatusBadRequest)
	}
	if !model.IsValidId(userID) || !model.IsValidId(resourceID) {
		return nil, model.NewAppError("EvaluatePluginAccessRequest", "app.access_control.plugin.invalid_id.app_error", nil, "", http.StatusBadRequest)
	}

	if !a.pluginAccessControlAvailable() {
		return &model.PluginAccessControlDecision{Outcome: model.AccessDecisionOutcomeUnavailable}, nil
	}

	// Subject build failures mean policy existence is unknowable → unavailable.
	user, appErr := a.GetUser(userID)
	if appErr != nil {
		rctx.Logger().Warn("Plugin access evaluation: failed to load user; returning unavailable",
			mlog.String("plugin_id", pluginID),
			mlog.String("user_id", userID),
			mlog.Err(appErr))
		return &model.PluginAccessControlDecision{Outcome: model.AccessDecisionOutcomeUnavailable}, nil
	}
	subject, appErr := a.BuildAccessControlSubject(rctx, userID, user.Roles, "")
	if appErr != nil {
		rctx.Logger().Warn("Plugin access evaluation: failed to build subject; returning unavailable",
			mlog.String("plugin_id", pluginID),
			mlog.String("user_id", userID),
			mlog.Err(appErr))
		return &model.PluginAccessControlDecision{Outcome: model.AccessDecisionOutcomeUnavailable}, nil
	}

	decision, evalErr := a.Srv().ch.AccessControl.AccessEvaluation(rctx, model.AccessRequest{
		Subject:  *subject,
		Resource: model.Resource{ID: resourceID, Type: resourceType},
		Action:   action,
	})
	if evalErr != nil {
		// The plugin lane only returns AppErrors for infra failures before
		// policy resolution (CEL eval errors are converted to deny inside
		// the evaluator), so policy existence is unknowable here.
		rctx.Logger().Warn("Plugin access evaluation: evaluator error; returning unavailable",
			mlog.String("plugin_id", pluginID),
			mlog.String("resource_id", resourceID),
			mlog.Err(evalErr))
		return &model.PluginAccessControlDecision{Outcome: model.AccessDecisionOutcomeUnavailable}, nil
	}

	switch decision.Outcome {
	case model.AccessDecisionOutcomeAllow,
		model.AccessDecisionOutcomeDeny,
		model.AccessDecisionOutcomeNoPolicy,
		model.AccessDecisionOutcomeUnavailable:
		return &model.PluginAccessControlDecision{Outcome: decision.Outcome}, nil
	default:
		// Fail closed without guessing from the collapsed boolean —
		// Decision==true is ambiguous between allow and no_policy.
		rctx.Logger().Warn("Plugin access evaluation: evaluator returned no outcome; returning unavailable",
			mlog.String("plugin_id", pluginID),
			mlog.String("resource_id", resourceID))
		return &model.PluginAccessControlDecision{Outcome: model.AccessDecisionOutcomeUnavailable}, nil
	}
}

// SavePluginAccessControlPolicy creates or updates a plugin-owned access
// control policy. Version is forced to v0.5 and Active to true (policy
// existence == enforcement; plugin types have no separate activation
// lifecycle). policy.ID must be the resource's stable ID — it is never
// generated here.
func (a *App) SavePluginAccessControlPolicy(rctx request.CTX, pluginID, actingUserID string, policy *model.AccessControlPolicy) (*model.AccessControlPolicy, *model.AppError) {
	acs := a.Srv().ch.AccessControl
	if acs == nil {
		return nil, model.NewAppError("SavePluginAccessControlPolicy", "app.pap.create_access_control_policy.app_error", nil, "Policy Administration Point is not initialized", http.StatusNotImplemented)
	}

	if policy == nil || policy.ID == "" {
		return nil, model.NewAppError("SavePluginAccessControlPolicy", "app.access_control.plugin.invalid_id.app_error", nil, "policy ID is required", http.StatusBadRequest)
	}

	auditRec := a.MakeAuditRecord(rctx, model.AuditEventSavePluginAccessControlPolicy, model.AuditStatusFail)
	defer a.LogAuditRec(rctx, auditRec, nil)
	model.AddEventParameterToAuditRec(auditRec, "actor", actingUserID)
	model.AddEventParameterToAuditRec(auditRec, "plugin_id", pluginID)
	model.AddEventParameterToAuditRec(auditRec, "resource_type", policy.Type)
	model.AddEventParameterAuditableToAuditRec(auditRec, "policy", policy)

	if _, appErr := a.pluginAccessControlScopeCheck("SavePluginAccessControlPolicy", pluginID, policy.Type); appErr != nil {
		return nil, appErr
	}
	if appErr := a.validatePluginActingUser("SavePluginAccessControlPolicy", actingUserID); appErr != nil {
		return nil, appErr
	}

	policy.Version = model.AccessControlPolicyVersionV0_5
	policy.Active = true

	// Prior-existence probe: create-vs-update for the audit trail, plus a
	// cross-type overwrite guard — a plugin must never overwrite a policy of
	// a different type sharing the ID (the ID space is global).
	operation := "update"
	existing, getErr := acs.GetPolicy(rctx, policy.ID)
	if getErr != nil {
		if getErr.StatusCode != http.StatusNotFound {
			return nil, getErr
		}
		operation = "create"
	} else if existing != nil && existing.Type != policy.Type {
		return nil, model.NewAppError("SavePluginAccessControlPolicy", "app.access_control.plugin.type_conflict.app_error", nil, "stored_type="+existing.Type, http.StatusBadRequest)
	}
	model.AddEventParameterToAuditRec(auditRec, "operation", operation)

	if appErr := policy.IsValid(); appErr != nil {
		return nil, appErr
	}

	// Thread the author: enterprise SavePolicy derives the caller ID from the
	// session (masking / CPA visibility / rank resolution), so synthesize one
	// for the acting user.
	saveCtx := rctx.WithSession(&model.Session{UserId: actingUserID})
	saved, appErr := acs.SavePolicy(saveCtx, policy)
	if appErr != nil {
		return nil, appErr
	}

	auditRec.Success()
	auditRec.AddEventResultState(saved)
	auditRec.AddEventObjectType("access_control_policy")

	return saved, nil
}

// GetPluginAccessControlPolicy returns the policy stored under id. Fails
// closed with 404 (no existence leak) when the stored policy's type is not a
// plugin type owned by the calling plugin.
func (a *App) GetPluginAccessControlPolicy(rctx request.CTX, pluginID, id string) (*model.AccessControlPolicy, *model.AppError) {
	acs := a.Srv().ch.AccessControl
	if acs == nil {
		return nil, model.NewAppError("GetPluginAccessControlPolicy", "app.pap.get_policy.app_error", nil, "Policy Administration Point is not initialized", http.StatusNotImplemented)
	}

	if !model.IsValidId(id) {
		return nil, model.NewAppError("GetPluginAccessControlPolicy", "app.access_control.plugin.invalid_id.app_error", nil, "", http.StatusBadRequest)
	}

	policy, appErr := acs.GetPolicy(rctx, id)
	if appErr != nil {
		return nil, appErr
	}

	rt, ok := model.PluginAccessControlResourceTypeFor(policy.Type)
	if !ok || !rt.IsOwnedBy(pluginID) {
		return nil, model.NewAppError("GetPluginAccessControlPolicy", "app.access_control.plugin.policy_not_found.app_error", nil, "", http.StatusNotFound)
	}

	return policy, nil
}

// DeletePluginAccessControlPolicy deletes the policy stored under id after
// verifying the stored policy's type equals resourceType and is owned by the
// calling plugin. Type mismatches fail closed with 404.
func (a *App) DeletePluginAccessControlPolicy(rctx request.CTX, pluginID, actingUserID, resourceType, id string) *model.AppError {
	acs := a.Srv().ch.AccessControl
	if acs == nil {
		return model.NewAppError("DeletePluginAccessControlPolicy", "app.pap.delete_policy.app_error", nil, "Policy Administration Point is not initialized", http.StatusNotImplemented)
	}

	auditRec := a.MakeAuditRecord(rctx, model.AuditEventDeletePluginAccessControlPolicy, model.AuditStatusFail)
	defer a.LogAuditRec(rctx, auditRec, nil)
	model.AddEventParameterToAuditRec(auditRec, "actor", actingUserID)
	model.AddEventParameterToAuditRec(auditRec, "plugin_id", pluginID)
	model.AddEventParameterToAuditRec(auditRec, "resource_type", resourceType)
	model.AddEventParameterToAuditRec(auditRec, "policy_id", id)
	model.AddEventParameterToAuditRec(auditRec, "operation", "delete")

	if _, appErr := a.pluginAccessControlScopeCheck("DeletePluginAccessControlPolicy", pluginID, resourceType); appErr != nil {
		return appErr
	}
	if appErr := a.validatePluginActingUser("DeletePluginAccessControlPolicy", actingUserID); appErr != nil {
		return appErr
	}
	if !model.IsValidId(id) {
		return model.NewAppError("DeletePluginAccessControlPolicy", "app.access_control.plugin.invalid_id.app_error", nil, "", http.StatusBadRequest)
	}

	policy, appErr := acs.GetPolicy(rctx, id)
	if appErr != nil {
		return appErr
	}

	// Fail closed: the stored type must match the requested type AND be owned
	// by the calling plugin.
	storedRT, ok := model.PluginAccessControlResourceTypeFor(policy.Type)
	if policy.Type != resourceType || !ok || !storedRT.IsOwnedBy(pluginID) {
		return model.NewAppError("DeletePluginAccessControlPolicy", "app.access_control.plugin.policy_not_found.app_error", nil, "", http.StatusNotFound)
	}

	if appErr := acs.DeletePolicy(rctx, id); appErr != nil {
		return appErr
	}

	model.AddEventParameterAuditableToAuditRec(auditRec, "policy", policy)
	auditRec.Success()

	return nil
}

// CheckPluginAccessControlExpression compiles and lints a CEL expression for
// a plugin-owned resource type; an empty slice means the expression is valid.
func (a *App) CheckPluginAccessControlExpression(rctx request.CTX, pluginID, actingUserID, resourceType, expression string) ([]model.CELExpressionError, *model.AppError) {
	if _, appErr := a.pluginAccessControlScopeCheck("CheckPluginAccessControlExpression", pluginID, resourceType); appErr != nil {
		return nil, appErr
	}
	if appErr := a.validatePluginActingUser("CheckPluginAccessControlExpression", actingUserID); appErr != nil {
		return nil, appErr
	}

	return a.CheckExpression(rctx.WithSession(&model.Session{UserId: actingUserID}), expression)
}

// QueryUsersForPluginAccessControlExpression returns the users matching the
// expression (test-modal support for plugin policy editors). limit is clamped
// to (0, pluginAccessControlQueryLimitMax].
func (a *App) QueryUsersForPluginAccessControlExpression(rctx request.CTX, pluginID, actingUserID, resourceType, expression, term, cursorID string, limit int) (*model.AccessControlPolicyTestResponse, *model.AppError) {
	if _, appErr := a.pluginAccessControlScopeCheck("QueryUsersForPluginAccessControlExpression", pluginID, resourceType); appErr != nil {
		return nil, appErr
	}
	if appErr := a.validatePluginActingUser("QueryUsersForPluginAccessControlExpression", actingUserID); appErr != nil {
		return nil, appErr
	}

	if limit <= 0 {
		limit = pluginAccessControlQueryLimitDefault
	}
	if limit > pluginAccessControlQueryLimitMax {
		limit = pluginAccessControlQueryLimitMax
	}

	users, total, appErr := a.TestExpression(rctx.WithSession(&model.Session{UserId: actingUserID}), expression, model.SubjectSearchOptions{
		Term:   term,
		Limit:  limit,
		Cursor: model.SubjectCursor{TargetID: cursorID},
	})
	if appErr != nil {
		return nil, appErr
	}

	return &model.AccessControlPolicyTestResponse{Users: users, Total: total}, nil
}

// GetPluginAccessControlFieldsAutocomplete returns CPA fields for plugin
// policy editor autocomplete. No resourceType scope check — field visibility
// is attribute-level, enforced by the underlying method via the acting user.
func (a *App) GetPluginAccessControlFieldsAutocomplete(rctx request.CTX, pluginID, actingUserID, after string, limit int) ([]*model.PropertyField, *model.AppError) {
	// The underlying method does not gate on the service; keep plugin
	// behavior uniform with the other proxies.
	if a.Srv().ch.AccessControl == nil {
		return nil, model.NewAppError("GetPluginAccessControlFieldsAutocomplete", "app.pap.get_access_control_auto_complete.app_error", nil, "Policy Administration Point is not initialized", http.StatusNotImplemented)
	}
	if appErr := a.validatePluginActingUser("GetPluginAccessControlFieldsAutocomplete", actingUserID); appErr != nil {
		return nil, appErr
	}

	if limit <= 0 {
		limit = pluginAccessControlQueryLimitDefault
	}
	if limit > pluginAccessControlQueryLimitMax {
		limit = pluginAccessControlQueryLimitMax
	}

	// An empty cursor means "first page"; the underlying search requires a
	// well-formed cursor ID, so map it to the lowest sentinel like api4 does.
	if after == "" {
		after = strings.Repeat("0", 26)
	}

	return a.GetAccessControlFieldsAutocomplete(rctx, after, limit, actingUserID)
}

// GetPluginAccessControlVisualAST converts a CEL expression to the visual
// (table) AST for plugin policy editors.
func (a *App) GetPluginAccessControlVisualAST(rctx request.CTX, pluginID, actingUserID, resourceType, expression string) (*model.VisualExpression, *model.AppError) {
	if _, appErr := a.pluginAccessControlScopeCheck("GetPluginAccessControlVisualAST", pluginID, resourceType); appErr != nil {
		return nil, appErr
	}
	if appErr := a.validatePluginActingUser("GetPluginAccessControlVisualAST", actingUserID); appErr != nil {
		return nil, appErr
	}

	return a.ExpressionToVisualAST(rctx.WithSession(&model.Session{UserId: actingUserID}), expression)
}
