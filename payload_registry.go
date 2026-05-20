package kmip

import (
	"sync"

	"github.com/pkg/errors"
)

// PayloadFactory builds an operation-specific request or response payload.
type PayloadFactory func() interface{}

type payloadFactoryKey struct {
	version   ProtocolVersion
	operation Enum
}

var (
	payloadFactoriesMu       sync.RWMutex
	requestPayloadFactories  = make(map[payloadFactoryKey]PayloadFactory)
	responsePayloadFactories = make(map[payloadFactoryKey]PayloadFactory)
)

// RegisterRequestPayloadFactory registers a version-specific request payload
// builder. It is intended for extension packages such as kmip20.
func RegisterRequestPayloadFactory(version ProtocolVersion, operation Enum, factory PayloadFactory) {
	payloadFactoriesMu.Lock()
	defer payloadFactoriesMu.Unlock()

	requestPayloadFactories[payloadFactoryKey{version: version, operation: operation}] = factory
}

// RegisterResponsePayloadFactory registers a version-specific response payload
// builder. It is intended for extension packages such as kmip20.
func RegisterResponsePayloadFactory(version ProtocolVersion, operation Enum, factory PayloadFactory) {
	payloadFactoriesMu.Lock()
	defer payloadFactoriesMu.Unlock()

	responsePayloadFactories[payloadFactoryKey{version: version, operation: operation}] = factory
}

// NewRequestPayload builds the request payload type for a KMIP version and
// operation. It falls back to the existing KMIP 1.x payloads when no
// version-specific factory is registered.
func NewRequestPayload(version ProtocolVersion, operation Enum) (interface{}, error) {
	payloadFactoriesMu.RLock()
	if factory, ok := requestPayloadFactories[payloadFactoryKey{version: version, operation: operation}]; ok {
		payloadFactoriesMu.RUnlock()
		return factory(), nil
	}
	payloadFactoriesMu.RUnlock()

	switch operation {
	case OPERATION_CREATE:
		return &CreateRequest{}, nil
	case OPERATION_CREATE_KEY_PAIR:
		return &CreateKeyPairRequest{}, nil
	case OPERATION_GET:
		return &GetRequest{}, nil
	case OPERATION_GET_ATTRIBUTES:
		return &GetAttributesRequest{}, nil
	case OPERATION_GET_ATTRIBUTE_LIST:
		return &GetAttributeListRequest{}, nil
	case OPERATION_DESTROY:
		return &DestroyRequest{}, nil
	case OPERATION_DISCOVER_VERSIONS:
		return &DiscoverVersionsRequest{}, nil
	case OPERATION_REGISTER:
		return &RegisterRequest{}, nil
	case OPERATION_ACTIVATE:
		return &ActivateRequest{}, nil
	case OPERATION_LOCATE:
		return &LocateRequest{}, nil
	case OPERATION_REVOKE:
		return &RevokeRequest{}, nil
	case OPERATION_REKEY:
		return &ReKeyRequest{}, nil
	case OPERATION_DECRYPT:
		return &DecryptRequest{}, nil
	case OPERATION_ENCRYPT:
		return &EncryptRequest{}, nil
	case OPERATION_QUERY:
		return &QueryRequest{}, nil
	case OPERATION_ADD_ATTRIBUTE:
		return &AddAttributeRequest{}, nil
	case OPERATION_MODIFY_ATTRIBUTE:
		return &ModifyAttributeRequest{}, nil
	case OPERATION_DELETE_ATTRIBUTE:
		return &DeleteAttributeRequest{}, nil
	default:
		return nil, errors.Errorf("unsupported operation: %v", operation)
	}
}

// NewResponsePayload builds the response payload type for a KMIP version and
// operation. It falls back to the existing KMIP 1.x payloads when no
// version-specific factory is registered.
func NewResponsePayload(version ProtocolVersion, operation Enum) (interface{}, error) {
	payloadFactoriesMu.RLock()
	if factory, ok := responsePayloadFactories[payloadFactoryKey{version: version, operation: operation}]; ok {
		payloadFactoriesMu.RUnlock()
		return factory(), nil
	}
	payloadFactoriesMu.RUnlock()

	switch operation {
	case OPERATION_CREATE:
		return &CreateResponse{}, nil
	case OPERATION_CREATE_KEY_PAIR:
		return &CreateKeyPairResponse{}, nil
	case OPERATION_GET:
		return &GetResponse{}, nil
	case OPERATION_GET_ATTRIBUTES:
		return &GetAttributesResponse{}, nil
	case OPERATION_GET_ATTRIBUTE_LIST:
		return &GetAttributeListResponse{}, nil
	case OPERATION_ACTIVATE:
		return &ActivateResponse{}, nil
	case OPERATION_REVOKE:
		return &RevokeResponse{}, nil
	case OPERATION_DESTROY:
		return &DestroyResponse{}, nil
	case OPERATION_DISCOVER_VERSIONS:
		return &DiscoverVersionsResponse{}, nil
	case OPERATION_ENCRYPT:
		return &EncryptResponse{}, nil
	case OPERATION_DECRYPT:
		return &DecryptResponse{}, nil
	case OPERATION_SIGN:
		return &SignResponse{}, nil
	case OPERATION_REGISTER:
		return &RegisterResponse{}, nil
	case OPERATION_LOCATE:
		return &LocateResponse{}, nil
	case OPERATION_REKEY:
		return &ReKeyResponse{}, nil
	case OPERATION_QUERY:
		return &QueryResponse{}, nil
	case OPERATION_ADD_ATTRIBUTE:
		return &AddAttributeResponse{}, nil
	case OPERATION_MODIFY_ATTRIBUTE:
		return &ModifyAttributeResponse{}, nil
	case OPERATION_DELETE_ATTRIBUTE:
		return &DeleteAttributeResponse{}, nil
	default:
		return nil, errors.Errorf("unsupported operation: %v", operation)
	}
}
