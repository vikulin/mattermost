// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/stretchr/testify/require"

	"github.com/mattermost/mattermost/server/v8/einterfaces/mocks"
)

// requirePluginRPCGobSafe gob-encodes v the way the plugin RPC layer encodes
// an API reply. The gob registrations from public/plugin's client_rpc init()
// are active because this package imports public/plugin. An unregistered
// concrete type inside an interface-typed field fails encoding, and net/rpc
// reacts by shutting down the SHARED plugin→server API connection — every
// subsequent plugin API call then fails with "connection is shut down".
func requirePluginRPCGobSafe(t *testing.T, v any) {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, gob.NewEncoder(&buf).Encode(v),
		"reply payload must gob-encode with client_rpc registrations; an unregistered concrete type inside `any` poisons the plugin RPC connection")
}

// TestPluginAccessControlGobSafety pins that every payload the plugin access
// control API can return over net/rpc survives gob encoding. The autocomplete
// subtest is the regression test for the native-attribute options bug: the
// bool-select options used to be []map[string]string inside Attrs
// (map[string]any), which gob rejects as unregistered and which fatally
// poisoned the plugin's RPC connection.
func TestPluginAccessControlGobSafety(t *testing.T) {
	th := Setup(t).InitBasic(t)
	actingUserID := th.BasicUser.Id

	t.Run("fields autocomplete response including native attribute fields", func(t *testing.T) {
		th.App.Srv().ch.AccessControl = &mocks.AccessControlServiceInterface{}

		fields, appErr := th.App.GetPluginAccessControlFieldsAutocomplete(th.Context, testAgentsPluginID, actingUserID, "", 100)
		require.Nil(t, appErr)
		require.NotEmpty(t, fields, "native attribute fields expected on the first page")

		// Prove the payload actually contains the risky part: a native
		// bool-select field carrying options inside Attrs.
		hasBoolSelect := false
		for _, f := range fields {
			if f.Attrs[model.PropertyFieldAttributeOptions] != nil {
				hasBoolSelect = true
			}
		}
		require.True(t, hasBoolSelect, "expected at least one native field with select options in Attrs")

		requirePluginRPCGobSafe(t, fields)
	})

	t.Run("policy with JSON-decoded Props", func(t *testing.T) {
		// Stored policies hydrate Props via json.Unmarshal into
		// map[string]any, so the concrete types inside are exactly
		// map[string]any, []any, string, float64, bool, and nil — all of
		// which gob accepts (the containers are registered by client_rpc,
		// the scalars are gob builtins). This test documents and pins that.
		var props map[string]any
		require.NoError(t, json.Unmarshal(
			[]byte(`{"nested":{"k":"v"},"list":[1,"two",true],"s":"x","n":1.5,"b":true,"z":null}`), &props))

		p := validPluginPolicy(model.NewId())
		p.Props = props
		requirePluginRPCGobSafe(t, p)
	})

	t.Run("visual AST with every runtime value shape", func(t *testing.T) {
		// The enterprise AST→visual conversion produces string, bool,
		// int64, uint64, float64, nil, and []any condition values.
		visual := &model.VisualExpression{Conditions: []model.Condition{
			{Attribute: "user.attributes.team", Operator: "==", Value: "eng"},
			{Attribute: "user.attributes.admin", Operator: "==", Value: true},
			{Attribute: "user.attributes.age", Operator: ">", Value: int64(30)},
			{Attribute: "user.attributes.count", Operator: "<", Value: uint64(10)},
			{Attribute: "user.attributes.score", Operator: ">=", Value: 1.5},
			{Attribute: "user.attributes.missing", Operator: "==", Value: nil},
			{Attribute: "user.attributes.role", Operator: "in", Value: []any{"a", "b"}},
		}}
		requirePluginRPCGobSafe(t, visual)
	})

	t.Run("expression check errors", func(t *testing.T) {
		requirePluginRPCGobSafe(t, []model.CELExpressionError{{Line: 1, Column: 2, Message: "boom"}})
	})

	t.Run("query users response with a real user", func(t *testing.T) {
		requirePluginRPCGobSafe(t, &model.AccessControlPolicyTestResponse{Users: []*model.User{th.BasicUser}, Total: 1})
	})

	t.Run("evaluation decision", func(t *testing.T) {
		requirePluginRPCGobSafe(t, &model.PluginAccessControlDecision{Outcome: model.AccessDecisionOutcomeAllow})
	})
}
