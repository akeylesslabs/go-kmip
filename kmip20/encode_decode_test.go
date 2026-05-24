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

func TestKMIP20_EncodeDecode_Get_Request(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_GET,
				RequestPayload: kmip.GetRequest{
					UniqueIdentifier: "49a1ca88-6bea-4fb2-b450-7e58802c3038",
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, kmip.GetRequest{}, decoded.BatchItems[0].RequestPayload)
}

func TestKMIP20_EncodeDecode_ReKey_Request(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_REKEY,
				RequestPayload: kmip.ReKeyRequest{
					UniqueIdentifier: "49a1ca88-6bea-4fb2-b450-7e58802c3038",
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, kmip.ReKeyRequest{}, decoded.BatchItems[0].RequestPayload)
}

func TestKMIP20_EncodeDecode_AddAttribute_Request(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_ADD_ATTRIBUTE,
				RequestPayload: kmip.AddAttributeRequest{
					UniqueIdentifier: "49a1ca88-6bea-4fb2-b450-7e58802c3038",
					Attribute: kmip.Attribute{
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
	require.IsType(t, kmip.AddAttributeRequest{}, decoded.BatchItems[0].RequestPayload)
}

func TestKMIP20_EncodeDecode_ModifyAttribute_Request(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_MODIFY_ATTRIBUTE,
				RequestPayload: kmip.ModifyAttributeRequest{
					UniqueIdentifier: "49a1ca88-6bea-4fb2-b450-7e58802c3038",
					Attribute: kmip.Attribute{
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
	require.IsType(t, kmip.ModifyAttributeRequest{}, decoded.BatchItems[0].RequestPayload)
}

func TestKMIP20_EncodeDecode_DeleteAttribute_Request(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_DELETE_ATTRIBUTE,
				RequestPayload: kmip.DeleteAttributeRequest{
					UniqueIdentifier: "49a1ca88-6bea-4fb2-b450-7e58802c3038",
					AttributeName:    "x-customAttribute",
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, kmip.DeleteAttributeRequest{}, decoded.BatchItems[0].RequestPayload)
}

func TestKMIP20_EncodeDecode_AdjustAttribute_Request(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_ADJUST_ATTRIBUTE,
				RequestPayload: AdjustAttributeRequest{
					UniqueIdentifier: "uid",
					AttributeRef: AttributeReference{
						Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH,
						Index: 0,
					},
					AdjustmentType:  kmip.Enum(1),
					AdjustmentValue: 32,
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, AdjustAttributeRequest{}, decoded.BatchItems[0].RequestPayload)
	ar := decoded.BatchItems[0].RequestPayload.(AdjustAttributeRequest)
	require.Equal(t, "uid", ar.UniqueIdentifier)
	require.Equal(t, kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH, ar.AttributeRef.Name)
}

func TestKMIP20_EncodeDecode_AdjustAttribute_Response(t *testing.T) {
	resp := kmip.Response{
		Header: kmip.ResponseHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.ResponseBatchItem{
			{
				Operation:       kmip.OPERATION_ADJUST_ATTRIBUTE,
				ResultStatus:    kmip.RESULT_STATUS_SUCCESS,
				ResponsePayload: AdjustAttributeResponse{UniqueIdentifier: "uid"},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(resp))

	var decoded kmip.Response
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, AdjustAttributeResponse{}, decoded.BatchItems[0].ResponsePayload)
	ar := decoded.BatchItems[0].ResponsePayload.(AdjustAttributeResponse)
	require.Equal(t, "uid", ar.UniqueIdentifier)
}

func TestKMIP20_EncodeDecode_Request_MultipleBatchItems(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 2,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_CREATE,
				RequestPayload: CreateRequest{
					ObjectType: kmip.OBJECT_TYPE_SYMMETRIC_KEY,
					Attributes: Attributes{
						Values: kmip.Attributes{
							{Name: kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM, Value: kmip.CRYPTO_AES},
							{Name: kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH, Value: int32(256)},
						},
					},
				},
			},
			{
				Operation: kmip.OPERATION_SET_ATTRIBUTE,
				RequestPayload: SetAttributeRequest{
					UniqueIdentifier: "uid",
					NewAttribute: kmip.Attribute{
						Name:  kmip.ATTRIBUTE_NAME_NAME,
						Value: kmip.Name{Value: "n", Type: kmip.NAME_TYPE_UNINTERPRETED_TEXT_STRING},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 2)
	require.IsType(t, CreateRequest{}, decoded.BatchItems[0].RequestPayload)
	require.IsType(t, SetAttributeRequest{}, decoded.BatchItems[1].RequestPayload)
}

func TestKMIP20_EncodeDecode_Response_MultipleBatchItems(t *testing.T) {
	resp := kmip.Response{
		Header: kmip.ResponseHeader{
			Version:    ProtocolVersion,
			BatchCount: 2,
		},
		BatchItems: []kmip.ResponseBatchItem{
			{
				Operation:       kmip.OPERATION_CREATE,
				ResultStatus:    kmip.RESULT_STATUS_SUCCESS,
				ResponsePayload: CreateResponse{ObjectType: kmip.OBJECT_TYPE_SYMMETRIC_KEY, UniqueIdentifier: "id1"},
			},
			{
				Operation:       kmip.OPERATION_SET_ATTRIBUTE,
				ResultStatus:    kmip.RESULT_STATUS_SUCCESS,
				ResponsePayload: SetAttributeResponse{UniqueIdentifier: "id2"},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(resp))

	var decoded kmip.Response
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 2)
	require.IsType(t, CreateResponse{}, decoded.BatchItems[0].ResponsePayload)
	require.IsType(t, SetAttributeResponse{}, decoded.BatchItems[1].ResponsePayload)
}

func TestKMIP14_EncodeDecode_UsesV1Payloads_WithKMIP20Registered(t *testing.T) {
	// Ensure kmip20 is imported and factories are registered
	_ = ProtocolVersion

	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    kmip.ProtocolVersion{Major: 1, Minor: 4},
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_CREATE,
				RequestPayload: kmip.CreateRequest{
					ObjectType: kmip.OBJECT_TYPE_SYMMETRIC_KEY,
					TemplateAttribute: kmip.TemplateAttribute{
						Attributes: kmip.Attributes{
							{Name: kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM, Value: kmip.CRYPTO_AES},
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
	require.IsType(t, kmip.CreateRequest{}, decoded.BatchItems[0].RequestPayload)
}
