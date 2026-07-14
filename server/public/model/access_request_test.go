// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccessDecisionOutcomeJSON(t *testing.T) {
	t.Run("no outcome keeps legacy wire shape", func(t *testing.T) {
		data, err := json.Marshal(AccessDecision{Decision: true})
		require.NoError(t, err)
		require.JSONEq(t, `{"decision":true}`, string(data))
	})

	t.Run("outcome round-trips", func(t *testing.T) {
		in := AccessDecision{Decision: false, Outcome: AccessDecisionOutcomeDeny}
		data, err := json.Marshal(in)
		require.NoError(t, err)
		require.JSONEq(t, `{"decision":false,"outcome":"deny"}`, string(data))

		var out AccessDecision
		require.NoError(t, json.Unmarshal(data, &out))
		require.Equal(t, in, out)
	})

	t.Run("plugin decision always carries outcome", func(t *testing.T) {
		data, err := json.Marshal(PluginAccessControlDecision{Outcome: AccessDecisionOutcomeNoPolicy})
		require.NoError(t, err)
		require.JSONEq(t, `{"outcome":"no_policy"}`, string(data))
	})
}
