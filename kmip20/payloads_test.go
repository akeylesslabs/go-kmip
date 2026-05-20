package kmip20

import (
	"bytes"
	"testing"

	"github.com/akeylesslabs/go-kmip"
	"github.com/stretchr/testify/require"
)

func TestPayloadRegistration(t *testing.T) {
	reqPayload, err := kmip.NewRequestPayload(ProtocolVersion, kmip.OPERATION_CREATE)
	require.NoError(t, err)
	require.IsType(t, &CreateRequest{}, reqPayload)

	respPayload, err := kmip.NewResponsePayload(ProtocolVersion, kmip.OPERATION_CREATE)
	require.NoError(t, err)
	require.IsType(t, &CreateResponse{}, respPayload)
}

func TestPayloadRegistrationDoesNotReplaceDefaultPayloads(t *testing.T) {
	reqPayload, err := kmip.NewRequestPayload(kmip.ProtocolVersion{Major: 1, Minor: 4}, kmip.OPERATION_CREATE)
	require.NoError(t, err)
	require.IsType(t, &kmip.CreateRequest{}, reqPayload)
}

func TestDecodeRequestUsesKMIP20PayloadForKMIP20Version(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_CREATE,
				RequestPayload: CreateRequest{
					ObjectType: kmip.OBJECT_TYPE_SYMMETRIC_KEY,
					Attributes: Attributes{},
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, CreateRequest{}, decoded.BatchItems[0].RequestPayload)
}

func TestDecodeResponseUsesKMIP20PayloadForKMIP20Version(t *testing.T) {
	resp := kmip.Response{
		Header: kmip.ResponseHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.ResponseBatchItem{
			{
				Operation:       kmip.OPERATION_CREATE,
				ResultStatus:    kmip.RESULT_STATUS_SUCCESS,
				ResponsePayload: CreateResponse{ObjectType: kmip.OBJECT_TYPE_SYMMETRIC_KEY, UniqueIdentifier: "id"},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(resp))

	var decoded kmip.Response
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, CreateResponse{}, decoded.BatchItems[0].ResponsePayload)
}
