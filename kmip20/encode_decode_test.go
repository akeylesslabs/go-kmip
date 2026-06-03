package kmip20

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/akeylesslabs/go-kmip"
	"github.com/stretchr/testify/require"
)

type testAttributesWrapper struct {
	kmip.Tag `kmip:"ATTRIBUTES"`

	NewAttribute Attributes `kmip:"NEW_ATTRIBUTE"`
}

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

func TestKMIP20_Decode_NewAttributeWithFalseBooleanValue(t *testing.T) {
	var sensitive bytes.Buffer
	writeTestTTLVHeader(&sensitive, kmip.SENSITIVE, 0x06, 8)
	sensitive.Write(make([]byte, 8))

	var newAttribute bytes.Buffer
	writeTestTTLVHeader(&newAttribute, kmip.NEW_ATTRIBUTE, 0x01, uint32(sensitive.Len()))
	newAttribute.Write(sensitive.Bytes())

	var payload bytes.Buffer
	writeTestTTLVHeader(&payload, kmip.ATTRIBUTES, 0x01, uint32(newAttribute.Len()))
	payload.Write(newAttribute.Bytes())

	var decoded testAttributesWrapper
	require.NoError(t, kmip.NewDecoder(bytes.NewReader(payload.Bytes())).Decode(&decoded))
	require.Len(t, decoded.NewAttribute.Values, 1)
	require.Equal(t, kmip.ATTRIBUTE_NAME_SENSITIVE, decoded.NewAttribute.Values[0].Name)
	require.Equal(t, false, decoded.NewAttribute.Values[0].Value)
}

func writeTestTTLVHeader(buf *bytes.Buffer, tag kmip.Tag, typ byte, length uint32) {
	var b [8]byte
	var tagBytes [4]byte
	binary.BigEndian.PutUint32(tagBytes[:], uint32(tag))
	copy(b[:3], tagBytes[1:])
	b[3] = typ
	binary.BigEndian.PutUint32(b[4:], length)
	buf.Write(b[:])
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

func TestKMIP20_EncodeDecode_CreateKeyPair_RequestWithDirectAttributes(t *testing.T) {
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
						CryptographicAlgorithm: kmip.CRYPTO_RSA,
						CryptographicLength:    2048,
					},
					PrivateKeyAttributes: Attributes{
						Name: kmip.Name{
							Value: "private-key",
							Type:  kmip.NAME_TYPE_UNINTERPRETED_TEXT_STRING,
						},
						CryptographicUsageMask: int32(kmip.CRYPTO_USAGE_MASK_SIGN),
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

	createKeyPair := decoded.BatchItems[0].RequestPayload.(CreateKeyPairRequest)
	require.Equal(t, kmip.CRYPTO_RSA, createKeyPair.CommonAttributes.Values.Get(kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM))
	require.Equal(t, int32(2048), createKeyPair.CommonAttributes.Values.Get(kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH))
	require.Equal(t, "private-key", createKeyPair.PrivateKeyAttributes.Values.Get(kmip.ATTRIBUTE_NAME_NAME).(kmip.Name).Value)
	require.Equal(t, int32(kmip.CRYPTO_USAGE_MASK_SIGN), createKeyPair.PrivateKeyAttributes.Values.Get(kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK))
}

func TestKMIP20_EncodeDecode_CreateKeyPair_RequestWithLegacyTemplateAttributes(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_CREATE_KEY_PAIR,
				RequestPayload: CreateKeyPairRequest{
					CommonTemplateAttribute: kmip.TemplateAttribute{
						Attributes: kmip.Attributes{
							{Name: kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM, Value: kmip.CRYPTO_RSA},
							{Name: kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH, Value: int32(2048)},
						},
					},
					PrivateKeyTemplateAttribute: kmip.TemplateAttribute{
						Attributes: kmip.Attributes{
							{
								Name: kmip.ATTRIBUTE_NAME_NAME,
								Value: kmip.Name{
									Value: "private-key",
									Type:  kmip.NAME_TYPE_UNINTERPRETED_TEXT_STRING,
								},
							},
							{Name: kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK, Value: int32(kmip.CRYPTO_USAGE_MASK_SIGN)},
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

	createKeyPair := decoded.BatchItems[0].RequestPayload.(CreateKeyPairRequest)
	require.Equal(t, kmip.CRYPTO_RSA, createKeyPair.CommonAttributes.Values.Get(kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM))
	require.Equal(t, int32(2048), createKeyPair.CommonAttributes.Values.Get(kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH))
	require.Equal(t, "private-key", createKeyPair.PrivateKeyAttributes.Values.Get(kmip.ATTRIBUTE_NAME_NAME).(kmip.Name).Value)
	require.Equal(t, int32(kmip.CRYPTO_USAGE_MASK_SIGN), createKeyPair.PrivateKeyAttributes.Values.Get(kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK))
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

func TestKMIP20_EncodeDecode_Register_RequestWithLegacyTemplateAttributes(t *testing.T) {
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
					TemplateAttribute: kmip.TemplateAttribute{
						Attributes: kmip.Attributes{
							{
								Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK,
								Value: int32(kmip.CRYPTO_USAGE_MASK_ENCRYPT),
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

	registerReq := decoded.BatchItems[0].RequestPayload.(RegisterRequest)
	require.Equal(t, int32(kmip.CRYPTO_USAGE_MASK_ENCRYPT), registerReq.Attributes.Values.Get(kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK))
}

func TestKMIP20_EncodeDecode_Create_RequestWithLegacyTemplateAttributes(t *testing.T) {
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
					TemplateAttribute: kmip.TemplateAttribute{
						Attributes: kmip.Attributes{
							{
								Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
								Value: kmip.CRYPTO_AES,
							},
							{
								Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH,
								Value: int32(256),
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
	require.IsType(t, CreateRequest{}, decoded.BatchItems[0].RequestPayload)

	createReq := decoded.BatchItems[0].RequestPayload.(CreateRequest)
	require.Equal(t, kmip.CRYPTO_AES, createReq.Attributes.Values.Get(kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM))
	require.Equal(t, int32(256), createReq.Attributes.Values.Get(kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH))
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
					NewAttribute: Attributes{
						CryptographicAlgorithm: kmip.CRYPTO_AES,
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
	require.Equal(t, kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM, sar.NewAttribute.Attribute().Name)
}

func TestKMIP20_EncodeDecode_AddAttribute_LegacyRequestPayload(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_ADD_ATTRIBUTE,
				RequestPayload: AddAttributeRequest{
					UniqueIdentifier: "uid",
					NewAttribute: []Attributes{{
						CryptographicAlgorithm: kmip.CRYPTO_AES,
					}},
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, AddAttributeRequest{}, decoded.BatchItems[0].RequestPayload)
	addAttribute := decoded.BatchItems[0].RequestPayload.(AddAttributeRequest)
	require.Equal(t, "uid", addAttribute.UniqueIdentifier)
	require.Equal(t, kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM, addAttribute.AttributeValue().Name)
}

func TestKMIP20_EncodeDecode_AddAttribute_RequestWithLegacyAttribute(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_ADD_ATTRIBUTE,
				RequestPayload: AddAttributeRequest{
					UniqueIdentifier: "uid",
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
	require.IsType(t, AddAttributeRequest{}, decoded.BatchItems[0].RequestPayload)
	addAttribute := decoded.BatchItems[0].RequestPayload.(AddAttributeRequest)
	require.Equal(t, "uid", addAttribute.UniqueIdentifier)
	require.Equal(t, kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM, addAttribute.AttributeValue().Name)
}

func TestKMIP20_EncodeDecode_AddAttribute_RequestWithDirectLegacyAttribute(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_ADD_ATTRIBUTE,
				RequestPayload: AddAttributeRequest{
					UniqueIdentifier: "uid",
					Attribute: kmip.Attribute{
						CryptographicAlgorithm: kmip.CRYPTO_AES,
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
	require.IsType(t, AddAttributeRequest{}, decoded.BatchItems[0].RequestPayload)
	addAttribute := decoded.BatchItems[0].RequestPayload.(AddAttributeRequest)
	require.Equal(t, "uid", addAttribute.UniqueIdentifier)
	require.Equal(t, kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM, addAttribute.AttributeValue().Name)
}

func TestKMIP20_EncodeDecode_AddAttribute_RequestWithNamedNewAttribute(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_ADD_ATTRIBUTE,
				RequestPayload: AddAttributeRequest{
					UniqueIdentifier: "uid",
					NewAttribute: []Attributes{{
						AttributeName:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
						AttributeValue: kmip.CRYPTO_AES,
					}},
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, AddAttributeRequest{}, decoded.BatchItems[0].RequestPayload)
	addAttribute := decoded.BatchItems[0].RequestPayload.(AddAttributeRequest)
	require.Equal(t, "uid", addAttribute.UniqueIdentifier)
	require.Equal(t, kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM, addAttribute.AttributeValue().Name)
	require.Equal(t, kmip.CRYPTO_AES, addAttribute.AttributeValue().Value)
}

func TestKMIP20_EncodeDecode_AddAttribute_RequestWithSensitiveNewAttribute(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_ADD_ATTRIBUTE,
				RequestPayload: AddAttributeRequest{
					UniqueIdentifier: "uid",
					NewAttribute: []Attributes{{
						Sensitive: true,
					}},
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, AddAttributeRequest{}, decoded.BatchItems[0].RequestPayload)
	addAttribute := decoded.BatchItems[0].RequestPayload.(AddAttributeRequest)
	require.Equal(t, "uid", addAttribute.UniqueIdentifier)
	require.Equal(t, kmip.ATTRIBUTE_NAME_SENSITIVE, addAttribute.AttributeValue().Name)
	require.Equal(t, true, addAttribute.AttributeValue().Value)
}

func TestKMIP20_EncodeDecode_AddAttribute_RequestWithNestedNewAttribute(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_ADD_ATTRIBUTE,
				RequestPayload: AddAttributeRequest{
					UniqueIdentifier: "uid",
					NewAttribute: []Attributes{{
						NewAttributes: []Attributes{{
							Sensitive: true,
						}},
					}},
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, AddAttributeRequest{}, decoded.BatchItems[0].RequestPayload)
	addAttribute := decoded.BatchItems[0].RequestPayload.(AddAttributeRequest)
	require.Equal(t, "uid", addAttribute.UniqueIdentifier)
	require.Equal(t, kmip.ATTRIBUTE_NAME_SENSITIVE, addAttribute.AttributeValue().Name)
	require.Equal(t, true, addAttribute.AttributeValue().Value)
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

func TestKMIP20_EncodeDecode_Activate_Request(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_ACTIVATE,
				RequestPayload: kmip.ActivateRequest{
					UniqueIdentifier: "uid",
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, kmip.ActivateRequest{}, decoded.BatchItems[0].RequestPayload)
	activate := decoded.BatchItems[0].RequestPayload.(kmip.ActivateRequest)
	require.Equal(t, "uid", activate.UniqueIdentifier)
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
				RequestPayload: ReKeyRequest{
					UniqueIdentifier: "uid",
					Offset:           time.Hour,
					Attributes: Attributes{
						CryptographicUsageMask: int32(kmip.CRYPTO_USAGE_MASK_ENCRYPT),
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
	require.IsType(t, ReKeyRequest{}, decoded.BatchItems[0].RequestPayload)
	rekey := decoded.BatchItems[0].RequestPayload.(ReKeyRequest)
	require.Equal(t, "uid", rekey.UniqueIdentifier)
	require.Equal(t, time.Hour, rekey.Offset)
	require.Equal(t, int32(kmip.CRYPTO_USAGE_MASK_ENCRYPT), rekey.Attributes.Values.Get(kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK))
}

func TestKMIP20_EncodeDecode_Revoke_Request(t *testing.T) {
	compromiseOccurrenceDate := time.Unix(1717000000, 0)
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_REVOKE,
				RequestPayload: RevokeRequest{
					UniqueIdentifier: "uid",
					RevocationReason: kmip.RevocationReason{
						RevocationReasonCode: kmip.REVOCATION_REASON_KEY_COMPROMISE,
						RevocationMessage:    "key compromised",
					},
					CompromiseOccurrenceDate: compromiseOccurrenceDate,
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))
	encoded := append([]byte(nil), buf.Bytes()...)

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, RevokeRequest{}, decoded.BatchItems[0].RequestPayload)
	revoke := decoded.BatchItems[0].RequestPayload.(RevokeRequest)
	require.Equal(t, "uid", revoke.UniqueIdentifier)
	require.Equal(t, kmip.REVOCATION_REASON_KEY_COMPROMISE, revoke.RevocationReason.RevocationReasonCode)
	require.Equal(t, "key compromised", revoke.RevocationReason.RevocationMessage)
	require.Equal(t, compromiseOccurrenceDate, revoke.CompromiseOccurrenceDate)

	revocationMessageHeader := []byte{0x42, 0x00, 0x80, byte(kmip.TEXT_STRING)}
	compromiseOccurrenceDateHeader := []byte{0x42, 0x00, 0x21, byte(kmip.DATE_TIME)}
	require.True(t, bytes.Contains(encoded, revocationMessageHeader))
	require.True(t, bytes.Contains(encoded, compromiseOccurrenceDateHeader))
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
	require.IsType(t, AddAttributeRequest{}, decoded.BatchItems[0].RequestPayload)
	addAttribute := decoded.BatchItems[0].RequestPayload.(AddAttributeRequest)
	require.Equal(t, kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM, addAttribute.AttributeValue().Name)
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
				RequestPayload: ModifyAttributeRequest{
					UniqueIdentifier: "uid",
					CurrentAttribute: Attributes{
						CryptographicUsageMask: int32(kmip.CRYPTO_USAGE_MASK_SIGN),
					},
					NewAttribute: Attributes{
						CryptographicUsageMask: int32(kmip.CRYPTO_USAGE_MASK_SIGN | kmip.CRYPTO_USAGE_MASK_VERIFY),
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
	require.IsType(t, ModifyAttributeRequest{}, decoded.BatchItems[0].RequestPayload)
	modifyAttribute := decoded.BatchItems[0].RequestPayload.(ModifyAttributeRequest)
	require.Equal(t, "uid", modifyAttribute.UniqueIdentifier)
	require.Equal(t, kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK, modifyAttribute.AttributeValue().Name)
	require.Equal(t, int32(kmip.CRYPTO_USAGE_MASK_SIGN|kmip.CRYPTO_USAGE_MASK_VERIFY), modifyAttribute.AttributeValue().Value)
}

func TestKMIP20_EncodeDecode_ModifyAttribute_RequestWithLegacyAttribute(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_MODIFY_ATTRIBUTE,
				RequestPayload: ModifyAttributeRequest{
					UniqueIdentifier: "uid",
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
	require.IsType(t, ModifyAttributeRequest{}, decoded.BatchItems[0].RequestPayload)
	modifyAttribute := decoded.BatchItems[0].RequestPayload.(ModifyAttributeRequest)
	require.Equal(t, "uid", modifyAttribute.UniqueIdentifier)
	require.Equal(t, kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM, modifyAttribute.AttributeValue().Name)
	require.Equal(t, kmip.CRYPTO_AES, modifyAttribute.AttributeValue().Value)
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
				RequestPayload: DeleteAttributeRequest{
					UniqueIdentifier: "uid",
					CurrentAttribute: Attributes{
						Name: kmip.Name{
							Value: "delete-name",
							Type:  kmip.NAME_TYPE_UNINTERPRETED_TEXT_STRING,
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
	require.IsType(t, DeleteAttributeRequest{}, decoded.BatchItems[0].RequestPayload)
	deleteAttr := decoded.BatchItems[0].RequestPayload.(DeleteAttributeRequest)
	require.Equal(t, "uid", deleteAttr.UniqueIdentifier)
	require.Equal(t, kmip.ATTRIBUTE_NAME_NAME, deleteAttr.AttributeNameValue())
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

func TestKMIP20_EncodeDecode_GetAttributes_Request(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_GET_ATTRIBUTES,
				RequestPayload: GetAttributesRequest{
					UniqueIdentifier: "uid",
					AttributeReferences: []AttributeReference{
						{Name: kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM},
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
	require.IsType(t, GetAttributesRequest{}, decoded.BatchItems[0].RequestPayload)
	getAttrs := decoded.BatchItems[0].RequestPayload.(GetAttributesRequest)
	require.Equal(t, "uid", getAttrs.UniqueIdentifier)
	require.Len(t, getAttrs.AttributeReferences, 1)
	require.Equal(t, kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM, getAttrs.AttributeReferences[0].Name)
}

func TestKMIP20_EncodeDecode_GetAttributes_RequestWithAttributeReferenceTags(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_GET_ATTRIBUTES,
				RequestPayload: GetAttributesRequest{
					UniqueIdentifier: "uid",
					AttributeReferenceTags: []kmip.Enum{
						kmip.Enum(kmip.CRYPTOGRAPHIC_ALGORITHM),
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))
	encoded := append([]byte(nil), buf.Bytes()...)

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, GetAttributesRequest{}, decoded.BatchItems[0].RequestPayload)
	getAttrs := decoded.BatchItems[0].RequestPayload.(GetAttributesRequest)
	require.Equal(t, "uid", getAttrs.UniqueIdentifier)
	require.Len(t, getAttrs.AttributeReferenceTags, 1)
	require.Equal(t, kmip.Enum(kmip.CRYPTOGRAPHIC_ALGORITHM), getAttrs.AttributeReferenceTags[0])
	require.Equal(t, []string{kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM}, getAttrs.AttributeReferenceNames())

	attributeRefHeader := []byte{0x42, 0x01, 0x3B, byte(kmip.ENUMERATION)}
	require.True(t, bytes.Contains(encoded, attributeRefHeader))
}

func TestKMIP20_EncodeDecode_GetAttributes_RequestWithLegacyAttributeNames(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_GET_ATTRIBUTES,
				RequestPayload: GetAttributesRequest{
					UniqueIdentifier: "uid",
					AttributeNames: []string{
						kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
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
	require.IsType(t, GetAttributesRequest{}, decoded.BatchItems[0].RequestPayload)
	getAttrs := decoded.BatchItems[0].RequestPayload.(GetAttributesRequest)
	require.Equal(t, "uid", getAttrs.UniqueIdentifier)
	require.Len(t, getAttrs.AttributeReferenceTags, 1)
	require.Equal(t, kmip.Enum(kmip.CRYPTOGRAPHIC_ALGORITHM), getAttrs.AttributeReferenceTags[0])
	require.Equal(t, []string{kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM}, getAttrs.AttributeReferenceNames())
}

func TestKMIP20_EncodeDecode_GetAttributes_Response(t *testing.T) {
	resp := kmip.Response{
		Header: kmip.ResponseHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.ResponseBatchItem{
			{
				Operation:    kmip.OPERATION_GET_ATTRIBUTES,
				ResultStatus: kmip.RESULT_STATUS_SUCCESS,
				ResponsePayload: GetAttributesResponse{
					UniqueIdentifier: "uid",
					Attributes: NewAttributeValues(kmip.Attributes{
						{Name: kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM, Value: kmip.CRYPTO_AES},
						{Name: kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK, Value: int32(0)},
						{Name: kmip.ATTRIBUTE_NAME_SENSITIVE, Value: false},
						{Name: kmip.ATTRIBUTE_NAME_COMPROMISE_DATE, Value: time.Unix(1717000000, 0)},
					}),
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(resp))
	encoded := append([]byte(nil), buf.Bytes()...)

	var decoded kmip.Response
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, GetAttributesResponse{}, decoded.BatchItems[0].ResponsePayload)
	getAttrs := decoded.BatchItems[0].ResponsePayload.(GetAttributesResponse)
	require.Equal(t, "uid", getAttrs.UniqueIdentifier)
	require.Equal(t, kmip.CRYPTO_AES, getAttrs.Attributes.Values.Get(kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM))
	require.Equal(t, int32(0), getAttrs.Attributes.Values.Get(kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK))
	require.Equal(t, false, getAttrs.Attributes.Values.Get(kmip.ATTRIBUTE_NAME_SENSITIVE))
	require.Equal(t, time.Unix(1717000000, 0), getAttrs.Attributes.Values.Get(kmip.ATTRIBUTE_NAME_COMPROMISE_DATE))

	legacyAttributeHeader := []byte{0x42, 0x00, 0x08, byte(kmip.STRUCTURE)}
	cryptoAlgorithmHeader := []byte{0x42, 0x00, 0x28, byte(kmip.ENUMERATION)}
	usageMaskHeader := []byte{0x42, 0x00, 0x2C, byte(kmip.INTEGER)}
	sensitiveHeader := []byte{0x42, 0x01, 0x20, byte(kmip.BOOLEAN)}
	compromiseDateHeader := []byte{0x42, 0x00, 0x20, byte(kmip.DATE_TIME)}
	require.False(t, bytes.Contains(encoded, legacyAttributeHeader))
	require.True(t, bytes.Contains(encoded, cryptoAlgorithmHeader))
	require.True(t, bytes.Contains(encoded, usageMaskHeader))
	require.True(t, bytes.Contains(encoded, sensitiveHeader))
	require.True(t, bytes.Contains(encoded, compromiseDateHeader))
}

func TestKMIP20_EncodeDecode_GetAttributeList_Request(t *testing.T) {
	req := kmip.Request{
		Header: kmip.RequestHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.RequestBatchItem{
			{
				Operation: kmip.OPERATION_GET_ATTRIBUTE_LIST,
				RequestPayload: GetAttributeListRequest{
					UniqueIdentifier: "uid",
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(req))

	var decoded kmip.Request
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, GetAttributeListRequest{}, decoded.BatchItems[0].RequestPayload)
	getAttrList := decoded.BatchItems[0].RequestPayload.(GetAttributeListRequest)
	require.Equal(t, "uid", getAttrList.UniqueIdentifier)
}

func TestKMIP20_EncodeDecode_GetAttributeList_Response(t *testing.T) {
	resp := kmip.Response{
		Header: kmip.ResponseHeader{
			Version:    ProtocolVersion,
			BatchCount: 1,
		},
		BatchItems: []kmip.ResponseBatchItem{
			{
				Operation:    kmip.OPERATION_GET_ATTRIBUTE_LIST,
				ResultStatus: kmip.RESULT_STATUS_SUCCESS,
				ResponsePayload: GetAttributeListResponse{
					UniqueIdentifier: "uid",
					AttributeReferences: []kmip.Enum{
						kmip.Enum(kmip.CRYPTOGRAPHIC_ALGORITHM),
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, kmip.NewEncoder(&buf).Encode(resp))
	encoded := append([]byte(nil), buf.Bytes()...)

	var decoded kmip.Response
	require.NoError(t, kmip.NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, GetAttributeListResponse{}, decoded.BatchItems[0].ResponsePayload)
	getAttrList := decoded.BatchItems[0].ResponsePayload.(GetAttributeListResponse)
	require.Equal(t, "uid", getAttrList.UniqueIdentifier)
	require.Len(t, getAttrList.AttributeReferences, 1)
	require.Equal(t, kmip.Enum(kmip.CRYPTOGRAPHIC_ALGORITHM), getAttrList.AttributeReferences[0])

	attributeRefHeader := []byte{0x42, 0x01, 0x3B, byte(kmip.ENUMERATION)}
	require.True(t, bytes.Contains(encoded, attributeRefHeader))
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
					NewAttribute: Attributes{
						Name: kmip.Name{Value: "n", Type: kmip.NAME_TYPE_UNINTERPRETED_TEXT_STRING},
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
