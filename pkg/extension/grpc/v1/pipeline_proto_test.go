//go:build unit

/*
Copyright 2025 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	"testing"
)

func TestActionType_EnumValues(t *testing.T) {
	tests := []struct {
		name     string
		value    ActionType
		wantName string
	}{
		{"unspecified", ActionType_ACTION_TYPE_UNSPECIFIED, "ACTION_TYPE_UNSPECIFIED"},
		{"grpc_method", ActionType_ACTION_TYPE_GRPC_METHOD, "ACTION_TYPE_GRPC_METHOD"},
		{"allow", ActionType_ACTION_TYPE_ALLOW, "ACTION_TYPE_ALLOW"},
		{"add_headers", ActionType_ACTION_TYPE_ADD_HEADERS, "ACTION_TYPE_ADD_HEADERS"},
		{"with_response_code", ActionType_ACTION_TYPE_WITH_RESPONSE_CODE, "ACTION_TYPE_WITH_RESPONSE_CODE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value.String() != tt.wantName {
				t.Errorf("ActionType(%d).String() = %q, want %q", tt.value, tt.value.String(), tt.wantName)
			}
		})
	}
}

func TestRequestActionEntry_FieldAccessors(t *testing.T) {
	entry := &RequestActionEntry{
		ActionType: ActionType_ACTION_TYPE_GRPC_METHOD,
		Predicates: []string{"request.headers['check'] == '1'"},
		Intention:  "checkThreatResponse.HeatLevel == 5",
		Method:     "checkThreatLevel",
	}

	if entry.GetActionType() != ActionType_ACTION_TYPE_GRPC_METHOD {
		t.Errorf("GetActionType() = %v, want %v", entry.GetActionType(), ActionType_ACTION_TYPE_GRPC_METHOD)
	}
	if len(entry.GetPredicates()) != 1 || entry.GetPredicates()[0] != "request.headers['check'] == '1'" {
		t.Errorf("GetPredicates() = %v, unexpected", entry.GetPredicates())
	}
	if entry.GetIntention() != "checkThreatResponse.HeatLevel == 5" {
		t.Errorf("GetIntention() = %q, unexpected", entry.GetIntention())
	}
	if entry.GetMethod() != "checkThreatLevel" {
		t.Errorf("GetMethod() = %q, unexpected", entry.GetMethod())
	}
}

func TestRequestActionEntry_NilSafeGetters(t *testing.T) {
	var entry *RequestActionEntry

	if entry.GetActionType() != ActionType_ACTION_TYPE_UNSPECIFIED {
		t.Errorf("GetActionType() on nil should return UNSPECIFIED")
	}
	if entry.GetPredicates() != nil {
		t.Errorf("GetPredicates() on nil should return nil")
	}
	if entry.GetIntention() != "" {
		t.Errorf("GetIntention() on nil should return empty string")
	}
	if entry.GetMethod() != "" {
		t.Errorf("GetMethod() on nil should return empty string")
	}
}

func TestResponseActionEntry_FieldAccessors(t *testing.T) {
	entry := &ResponseActionEntry{
		ActionType:      ActionType_ACTION_TYPE_ADD_HEADERS,
		Predicates:      []string{"response.code == 200"},
		HeadersToAdd:    "{'x-threat-checked': 'true'}",
		NewResponseCode: 0,
	}

	if entry.GetActionType() != ActionType_ACTION_TYPE_ADD_HEADERS {
		t.Errorf("GetActionType() = %v, want %v", entry.GetActionType(), ActionType_ACTION_TYPE_ADD_HEADERS)
	}
	if len(entry.GetPredicates()) != 1 {
		t.Errorf("GetPredicates() = %v, unexpected", entry.GetPredicates())
	}
	if entry.GetHeadersToAdd() != "{'x-threat-checked': 'true'}" {
		t.Errorf("GetHeadersToAdd() = %q, unexpected", entry.GetHeadersToAdd())
	}
	if entry.GetNewResponseCode() != 0 {
		t.Errorf("GetNewResponseCode() = %d, want 0", entry.GetNewResponseCode())
	}

	// Test with_response_code type
	codeEntry := &ResponseActionEntry{
		ActionType:      ActionType_ACTION_TYPE_WITH_RESPONSE_CODE,
		NewResponseCode: 403,
	}
	if codeEntry.GetNewResponseCode() != 403 {
		t.Errorf("GetNewResponseCode() = %d, want 403", codeEntry.GetNewResponseCode())
	}
}

func TestResponseActionEntry_NilSafeGetters(t *testing.T) {
	var entry *ResponseActionEntry

	if entry.GetActionType() != ActionType_ACTION_TYPE_UNSPECIFIED {
		t.Errorf("GetActionType() on nil should return UNSPECIFIED")
	}
	if entry.GetPredicates() != nil {
		t.Errorf("GetPredicates() on nil should return nil")
	}
	if entry.GetHeadersToAdd() != "" {
		t.Errorf("GetHeadersToAdd() on nil should return empty string")
	}
	if entry.GetNewResponseCode() != 0 {
		t.Errorf("GetNewResponseCode() on nil should return 0")
	}
}

func TestPipelineOnRequestRequest_FieldAccessors(t *testing.T) {
	policy := &Policy{
		Metadata: &Metadata{
			Kind:      "ThreatPolicy",
			Namespace: "default",
			Name:      "my-policy",
		},
	}
	actions := []*RequestActionEntry{
		{
			ActionType: ActionType_ACTION_TYPE_GRPC_METHOD,
			Method:     "checkThreatLevel",
			Intention:  "checkThreatLevelResponse.HeatLevel == 5",
		},
		{
			ActionType: ActionType_ACTION_TYPE_ALLOW,
			Intention:  "request.auth.identity.admin == true",
		},
	}

	req := &PipelineOnRequestRequest{
		Policy:  policy,
		Actions: actions,
	}

	if req.GetPolicy() != policy {
		t.Errorf("GetPolicy() returned unexpected value")
	}
	if len(req.GetActions()) != 2 {
		t.Fatalf("GetActions() length = %d, want 2", len(req.GetActions()))
	}
	if req.GetActions()[0].GetMethod() != "checkThreatLevel" {
		t.Errorf("first action Method = %q, want %q", req.GetActions()[0].GetMethod(), "checkThreatLevel")
	}
	if req.GetActions()[1].GetActionType() != ActionType_ACTION_TYPE_ALLOW {
		t.Errorf("second action type = %v, want ALLOW", req.GetActions()[1].GetActionType())
	}
}

func TestPipelineOnRequestRequest_NilSafeGetters(t *testing.T) {
	var req *PipelineOnRequestRequest

	if req.GetPolicy() != nil {
		t.Errorf("GetPolicy() on nil should return nil")
	}
	if req.GetActions() != nil {
		t.Errorf("GetActions() on nil should return nil")
	}
}

func TestPipelineOnResponseRequest_FieldAccessors(t *testing.T) {
	policy := &Policy{
		Metadata: &Metadata{
			Kind:      "ThreatPolicy",
			Namespace: "default",
			Name:      "my-policy",
		},
	}
	actions := []*ResponseActionEntry{
		{
			ActionType:   ActionType_ACTION_TYPE_ADD_HEADERS,
			HeadersToAdd: "{'x-threat-checked': 'true'}",
		},
		{
			ActionType:      ActionType_ACTION_TYPE_WITH_RESPONSE_CODE,
			NewResponseCode: 429,
		},
	}

	req := &PipelineOnResponseRequest{
		Policy:  policy,
		Actions: actions,
	}

	if req.GetPolicy() != policy {
		t.Errorf("GetPolicy() returned unexpected value")
	}
	if len(req.GetActions()) != 2 {
		t.Fatalf("GetActions() length = %d, want 2", len(req.GetActions()))
	}
	if req.GetActions()[0].GetHeadersToAdd() != "{'x-threat-checked': 'true'}" {
		t.Errorf("first action HeadersToAdd = %q, unexpected", req.GetActions()[0].GetHeadersToAdd())
	}
	if req.GetActions()[1].GetNewResponseCode() != 429 {
		t.Errorf("second action NewResponseCode = %d, want 429", req.GetActions()[1].GetNewResponseCode())
	}
}

func TestPipelineOnResponseRequest_NilSafeGetters(t *testing.T) {
	var req *PipelineOnResponseRequest

	if req.GetPolicy() != nil {
		t.Errorf("GetPolicy() on nil should return nil")
	}
	if req.GetActions() != nil {
		t.Errorf("GetActions() on nil should return nil")
	}
}

func TestPipelineRPC_FullMethodNames(t *testing.T) {
	tests := []struct {
		name     string
		got      string
		expected string
	}{
		{
			"PipelineOnRequest",
			ExtensionService_PipelineOnRequest_FullMethodName,
			"/kuadrant.v1.ExtensionService/PipelineOnRequest",
		},
		{
			"PipelineOnResponse",
			ExtensionService_PipelineOnResponse_FullMethodName,
			"/kuadrant.v1.ExtensionService/PipelineOnResponse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("FullMethodName = %q, want %q", tt.got, tt.expected)
			}
		})
	}
}
