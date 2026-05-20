package kmip20

import (
	"bytes"
	"testing"

	"github.com/akeylesslabs/go-kmip"
	"github.com/stretchr/testify/require"
)

func TestKMIP20_EncodeDecode_Create_Request(t *testing.T) {
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
	cr := decoded.BatchItems[0].RequestPayload.(CreateRequest)
	require.Equal(t, kmip.OBJECT_TYPE_SYMMETRIC_KEY, cr.ObjectType)
}

func TestKMIP20_EncodeDecode_Create_Response(t *testing.T) {
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
	cr := decoded.BatchItems[0].ResponsePayload.(CreateResponse)
	require.Equal(t, kmip.OBJECT_TYPE_SYMMETRIC_KEY, cr.ObjectType)
	require.Equal(t, "id", cr.UniqueIdentifier)
}

func TestKMIP20_EncodeDecode_CreateKeyPair_Request(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_CREATE_KEY_PAIR,
				RequestPayload: CreateKeyPairRequest{
					CommonAttributes: Attributes{
						Values: kmip.Attributes{
							{
								Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
								Value: kmip.CRYPTO_RSA,
							},
							{
								Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH,
								Value: int32(2048),
							},
						},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, CreateKeyPairRequest{}, decoded.BatchItems[0].RequestPayload)
}

func TestKMIP20_EncodeDecode_Register_Request(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_REGISTER,
				RequestPayload: RegisterRequest{
					ObjectType: kmip.OBJECT_TYPE_SYMMETRIC_KEY,
					Attributes: Attributes{
						Values: kmip.Attributes{
							{
								Name:  kmip.ATTRIBUTE_NAME_NAME,
								Value: kmip.Name{Value: "name", Type: kmip.NAME_TYPE_UNINTERPRETED_TEXT_STRING},
							},
						},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, RegisterRequest{}, decoded.BatchItems[0].RequestPayload)
}

func TestKMIP20_EncodeDecode_Locate_Request(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_LOCATE,
				RequestPayload: LocateRequest{
					MaximumItems: 1,
					Attributes: Attributes{
						Values: kmip.Attributes{
							{
								Name:  kmip.ATTRIBUTE_NAME_OBJECT_TYPE,
								Value: kmip.OBJECT_TYPE_SYMMETRIC_KEY,
							},
						},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, LocateRequest{}, decoded.BatchItems[0].RequestPayload)
}

func TestKMIP20_EncodeDecode_SetAttribute_Request(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_SET_ATTRIBUTE,
				RequestPayload: SetAttributeRequest{
					UniqueIdentifier: "uid",
					NewAttribute: kmip.Attribute{
						Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
						Value: kmip.CRYPTO_AES,
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, SetAttributeRequest{}, decoded.BatchItems[0].RequestPayload)
	sar := decoded.BatchItems[0].RequestPayload.(SetAttributeRequest)
	require.Equal(t, "uid", sar.UniqueIdentifier)
	require.Equal(t, kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM, sar.NewAttribute.Name)
}
