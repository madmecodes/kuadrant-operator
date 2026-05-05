package types

import "context"

// ActionType discriminates how the wasm-shim dispatches an action.
type ActionType string

const (
	ActionTypeGRPCMethod       ActionType = "grpc_method"
	ActionTypeAllow            ActionType = "allow"
	ActionTypeAddHeaders       ActionType = "add_headers"
	ActionTypeWithResponseCode ActionType = "with_response_code"
)

// RequestAction is the interface implemented by actions that can be used
// in the request phase of a pipeline.
type RequestAction interface {
	requestActionType() ActionType
}

// ResponseAction is the interface implemented by actions that can be used
// in the response phase of a pipeline.
type ResponseAction interface {
	responseActionType() ActionType
}

// GRPCMethodAction invokes a registered gRPC action method and evaluates
// the response. Implements RequestAction.
type GRPCMethodAction struct {
	Predicate []string // CEL predicates — if any is false, skip this action
	Intention string   // CEL expression evaluated against the gRPC response
	Method    string   // Name of a registered ActionMethod
	Var       string   // Variable name for the gRPC response (used by onReply predicates)
}

func (a GRPCMethodAction) requestActionType() ActionType { return ActionTypeGRPCMethod }

// AllowAction permits or denies the request based on request attributes only.
// No gRPC call is made. Implements RequestAction.
type AllowAction struct {
	Predicate []string // CEL predicates — if any is false, skip this action
	Intention string   // CEL expression — if false, deny the request
}

func (a AllowAction) requestActionType() ActionType { return ActionTypeAllow }

// AddHeadersAction adds headers to the response. Implements ResponseAction.
type AddHeadersAction struct {
	Predicate    []string // CEL predicates — if any is false, skip this action
	HeadersToAdd string   // CEL expression evaluating to a map of headers to add
}

func (a AddHeadersAction) responseActionType() ActionType { return ActionTypeAddHeaders }

// WithResponseCodeAction modifies the HTTP response code. Implements ResponseAction.
type WithResponseCodeAction struct {
	Predicate       []string // CEL predicates — if any is false, skip this action
	NewResponseCode int      // HTTP status code to set on the response
}

func (a WithResponseCodeAction) responseActionType() ActionType { return ActionTypeWithResponseCode }

// Pipeline provides a builder for composing ordered actions on request
// and response phases. Each OnRequest/OnResponse call sends a single gRPC
// message to the operator containing all supplied actions.
type Pipeline interface {
	OnRequest(ctx context.Context, actions ...RequestAction) error
	OnResponse(ctx context.Context, actions ...ResponseAction) error
}
