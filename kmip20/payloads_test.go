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

	activateReqPayload, err := kmip.NewRequestPayload(ProtocolVersion, kmip.OPERATION_ACTIVATE)
	require.NoError(t, err)
	require.IsType(t, &kmip.ActivateRequest{}, activateReqPayload)

	activateRespPayload, err := kmip.NewResponsePayload(ProtocolVersion, kmip.OPERATION_ACTIVATE)
	require.NoError(t, err)
	require.IsType(t, &kmip.ActivateResponse{}, activateRespPayload)

	getAttrsReqPayload, err := kmip.NewRequestPayload(ProtocolVersion, kmip.OPERATION_GET_ATTRIBUTES)
	require.NoError(t, err)
	require.IsType(t, &GetAttributesRequest{}, getAttrsReqPayload)

	getAttrsRespPayload, err := kmip.NewResponsePayload(ProtocolVersion, kmip.OPERATION_GET_ATTRIBUTES)
	require.NoError(t, err)
	require.IsType(t, &GetAttributesResponse{}, getAttrsRespPayload)

	getAttrListReqPayload, err := kmip.NewRequestPayload(ProtocolVersion, kmip.OPERATION_GET_ATTRIBUTE_LIST)
	require.NoError(t, err)
	require.IsType(t, &GetAttributeListRequest{}, getAttrListReqPayload)

	getAttrListRespPayload, err := kmip.NewResponsePayload(ProtocolVersion, kmip.OPERATION_GET_ATTRIBUTE_LIST)
	require.NoError(t, err)
	require.IsType(t, &GetAttributeListResponse{}, getAttrListRespPayload)

	encryptReqPayload, err := kmip.NewRequestPayload(ProtocolVersion, kmip.OPERATION_ENCRYPT)
	require.NoError(t, err)
	require.IsType(t, &EncryptRequest{}, encryptReqPayload)

	decryptReqPayload, err := kmip.NewRequestPayload(ProtocolVersion, kmip.OPERATION_DECRYPT)
	require.NoError(t, err)
	require.IsType(t, &DecryptRequest{}, decryptReqPayload)

	queryReqPayload, err := kmip.NewRequestPayload(ProtocolVersion, kmip.OPERATION_QUERY)
	require.NoError(t, err)
	require.IsType(t, &QueryRequest{}, queryReqPayload)

	revokeReqPayload, err := kmip.NewRequestPayload(ProtocolVersion, kmip.OPERATION_REVOKE)
	require.NoError(t, err)
	require.IsType(t, &RevokeRequest{}, revokeReqPayload)

	revokeRespPayload, err := kmip.NewResponsePayload(ProtocolVersion, kmip.OPERATION_REVOKE)
	require.NoError(t, err)
	require.IsType(t, &RevokeResponse{}, revokeRespPayload)

	rekeyReqPayload, err := kmip.NewRequestPayload(ProtocolVersion, kmip.OPERATION_REKEY)
	require.NoError(t, err)
	require.IsType(t, &ReKeyRequest{}, rekeyReqPayload)

	rekeyRespPayload, err := kmip.NewResponsePayload(ProtocolVersion, kmip.OPERATION_REKEY)
	require.NoError(t, err)
	require.IsType(t, &ReKeyResponse{}, rekeyRespPayload)

	deleteAttrReqPayload, err := kmip.NewRequestPayload(ProtocolVersion, kmip.OPERATION_DELETE_ATTRIBUTE)
	require.NoError(t, err)
	require.IsType(t, &DeleteAttributeRequest{}, deleteAttrReqPayload)

	deleteAttrRespPayload, err := kmip.NewResponsePayload(ProtocolVersion, kmip.OPERATION_DELETE_ATTRIBUTE)
	require.NoError(t, err)
	require.IsType(t, &DeleteAttributeResponse{}, deleteAttrRespPayload)
}

func TestPayloadRegistrationDoesNotReplaceDefaultPayloads(t *testing.T) {
	reqPayload, err := kmip.NewRequestPayload(kmip.ProtocolVersion{Major: 1, Minor: 4}, kmip.OPERATION_CREATE)
	require.NoError(t, err)
	require.IsType(t, &kmip.CreateRequest{}, reqPayload)

	reqPayload, err = kmip.NewRequestPayload(kmip.ProtocolVersion{Major: 1, Minor: 4}, kmip.OPERATION_QUERY)
	require.NoError(t, err)
	require.IsType(t, &kmip.QueryRequest{}, reqPayload)
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

func TestDecodeQueryRequestUsesKMIP20PayloadForKMIP20Version(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_QUERY,
				RequestPayload: QueryRequest{
					QueryFunctions: []kmip.Enum{kmip.QUERY_OPERATIONS},
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, QueryRequest{}, decoded.BatchItems[0].RequestPayload)

	query := decoded.BatchItems[0].RequestPayload.(QueryRequest)
	require.Equal(t, []kmip.Enum{kmip.QUERY_OPERATIONS}, query.QueryFunctions)
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

func TestAttributes_EncodeDecode(t *testing.T) {
	attrs := Attributes{
		Values: kmip.Attributes{
			{
				Name: kmip.ATTRIBUTE_NAME_NAME,
				Value: kmip.Name{
					Value: "obj",
					Type:  kmip.NAME_TYPE_UNINTERPRETED_TEXT_STRING,
				},
			},
			{
				Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
				Value: kmip.CRYPTO_AES,
			},
			{
				Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH,
				Value: int32(256),
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(attrs))

	var decoded Attributes
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))

	require.Len(t, decoded.Values, 3)
	require.Equal(t, kmip.ATTRIBUTE_NAME_NAME, decoded.Values[0].Name)
	require.IsType(t, kmip.Name{}, decoded.Values[0].Value)
	require.Equal(t, kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM, decoded.Values[1].Name)
	require.Equal(t, kmip.CRYPTO_AES, decoded.Values[1].Value)
	require.Equal(t, kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH, decoded.Values[2].Name)
	require.Equal(t, int32(256), decoded.Values[2].Value)
}
