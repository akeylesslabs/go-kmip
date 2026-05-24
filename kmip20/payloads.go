package kmip20

import "github.com/akeylesslabs/go-kmip"

// ProtocolVersion is the KMIP 2.0 protocol version.
var ProtocolVersion = kmip.ProtocolVersion{Major: 2, Minor: 0}

func init() {
	registerRequestPayloads()
	registerResponsePayloads()
}

func registerRequestPayloads() {
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_CREATE, func() interface{} {
		return &CreateRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_CREATE_KEY_PAIR, func() interface{} {
		return &CreateKeyPairRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_GET, func() interface{} {
		// KMIP 2.0 Get payload is compatible with 1.x structure
		return &kmip.GetRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_REGISTER, func() interface{} {
		return &RegisterRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_LOCATE, func() interface{} {
		return &LocateRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_REKEY, func() interface{} {
		// KMIP 2.0 ReKey payload remains compatible with 1.x structure
		return &kmip.ReKeyRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_ADD_ATTRIBUTE, func() interface{} {
		// Though KMIP 2.0 introduces SetAttribute/AdjustAttribute, AddAttribute can still be handled
		return &kmip.AddAttributeRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_MODIFY_ATTRIBUTE, func() interface{} {
		return &kmip.ModifyAttributeRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_DELETE_ATTRIBUTE, func() interface{} {
		return &kmip.DeleteAttributeRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_ADJUST_ATTRIBUTE, func() interface{} {
		return &AdjustAttributeRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_SET_ATTRIBUTE, func() interface{} {
		return &SetAttributeRequest{}
	})
}

func registerResponsePayloads() {
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_CREATE, func() interface{} {
		return &CreateResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_CREATE_KEY_PAIR, func() interface{} {
		return &CreateKeyPairResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_GET, func() interface{} {
		return &kmip.GetResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_REGISTER, func() interface{} {
		return &RegisterResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_LOCATE, func() interface{} {
		return &LocateResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_REKEY, func() interface{} {
		return &kmip.ReKeyResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_ADD_ATTRIBUTE, func() interface{} {
		return &kmip.AddAttributeResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_MODIFY_ATTRIBUTE, func() interface{} {
		return &kmip.ModifyAttributeResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_DELETE_ATTRIBUTE, func() interface{} {
		return &kmip.DeleteAttributeResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_ADJUST_ATTRIBUTE, func() interface{} {
		return &AdjustAttributeResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_SET_ATTRIBUTE, func() interface{} {
		return &SetAttributeResponse{}
	})
}

// Attributes is the KMIP 2.0 Attributes structure.
type Attributes struct {
	kmip.Tag `kmip:"ATTRIBUTES"`

	Values kmip.Attributes `kmip:"ATTRIBUTE"`
}

// CreateRequest is the KMIP 2.0 Create request payload.
type CreateRequest struct {
	ObjectType             kmip.Enum  `kmip:"OBJECT_TYPE,required"`
	Attributes             Attributes `kmip:"ATTRIBUTES,required"`
	ProtectionStorageMasks kmip.Enum  `kmip:"PROTECTION_STORAGE_MASKS"`
}

// CreateResponse is the KMIP 2.0 Create response payload.
type CreateResponse struct {
	ObjectType       kmip.Enum `kmip:"OBJECT_TYPE,required"`
	UniqueIdentifier string    `kmip:"UNIQUE_IDENTIFIER,required"`
}

// CreateKeyPairRequest is the KMIP 2.0 Create Key Pair request payload.
type CreateKeyPairRequest struct {
	CommonAttributes                 Attributes `kmip:"COMMON_ATTRIBUTES"`
	PrivateKeyAttributes             Attributes `kmip:"PRIVATE_KEY_ATTRIBUTES"`
	PublicKeyAttributes              Attributes `kmip:"PUBLIC_KEY_ATTRIBUTES"`
	CommonProtectionStorageMasks     kmip.Enum  `kmip:"PROTECTION_STORAGE_MASKS"`
	PrivateKeyProtectionStorageMasks kmip.Enum  `kmip:"PROTECTION_STORAGE_MASKS"`
	PublicKeyProtectionStorageMasks  kmip.Enum  `kmip:"PROTECTION_STORAGE_MASKS"`
}

// CreateKeyPairResponse is the KMIP 2.0 Create Key Pair response payload.
type CreateKeyPairResponse struct {
	PrivateKeyUniqueIdentifier string `kmip:"PRIVATE_KEY_UNIQUE_IDENTIFIER,required"`
	PublicKeyUniqueIdentifier  string `kmip:"PUBLIC_KEY_UNIQUE_IDENTIFIER,required"`
}

// RegisterRequest is the KMIP 2.0 Register request payload.
type RegisterRequest struct {
	ObjectType kmip.Enum  `kmip:"OBJECT_TYPE,required"`
	Attributes Attributes `kmip:"ATTRIBUTES,required"`

	SymmetricKey kmip.SymmetricKey `kmip:"SYMMETRIC_KEY"`
	PrivateKey   kmip.PrivateKey   `kmip:"PRIVATE_KEY"`
	PublicKey    kmip.PublicKey    `kmip:"PUBLIC_KEY"`
	Certificate  kmip.Certificate  `kmip:"CERTIFICATE"`
	OpaqueObject kmip.OpaqueObject `kmip:"OPAQUE_OBJECT"`
}

// RegisterResponse is the KMIP 2.0 Register response payload.
type RegisterResponse struct {
	UniqueIdentifier string `kmip:"UNIQUE_IDENTIFIER,required"`
}

// LocateRequest is the KMIP 2.0 Locate request payload.
type LocateRequest struct {
	MaximumItems      int32      `kmip:"MAXIMUM_ITEMS"`
	OffsetItems       int32      `kmip:"OFFSET_ITEMS"`
	StorageStatusMask int32      `kmip:"STORAGE_STATUS_MASK"`
	ObjectGroupMember kmip.Enum  `kmip:"OBJECT_GROUP_MEMBER"`
	Attributes        Attributes `kmip:"ATTRIBUTES"`
}

// LocateResponse is the KMIP 2.0 Locate response payload.
type LocateResponse struct {
	LocatedItems      int32    `kmip:"LOCATED_ITEMS"`
	UniqueIdentifiers []string `kmip:"UNIQUE_IDENTIFIER"`
}

// SetAttributeRequest is the KMIP 2.0 Set Attribute request payload.
type SetAttributeRequest struct {
	UniqueIdentifier string         `kmip:"UNIQUE_IDENTIFIER"`
	NewAttribute     kmip.Attribute `kmip:"NEW_ATTRIBUTE,required"`
}

// SetAttributeResponse is the KMIP 2.0 Set Attribute response payload.
type SetAttributeResponse struct {
	UniqueIdentifier string `kmip:"UNIQUE_IDENTIFIER,required"`
}

// AttributeReference is the KMIP 2.0 Attribute Reference structure.
type AttributeReference struct {
	kmip.Tag `kmip:"ATTRIBUTE_REFERENCE"`

	Name  string `kmip:"ATTRIBUTE_NAME,required"`
	Index int32  `kmip:"ATTRIBUTE_INDEX"`
}

// AdjustAttributeRequest is the KMIP 2.0 Adjust Attribute request payload.
type AdjustAttributeRequest struct {
	UniqueIdentifier string             `kmip:"UNIQUE_IDENTIFIER"`
	AttributeRef     AttributeReference `kmip:"ATTRIBUTE_REFERENCE,required"`
	AdjustmentType   kmip.Enum          `kmip:"ADJUSTMENT_TYPE,required"`
	AdjustmentValue  int32              `kmip:"ADJUSTMENT_VALUE"`
	CurrentAttribute kmip.Attribute     `kmip:"CURRENT_ATTRIBUTE"`
	NewAttribute     kmip.Attribute     `kmip:"NEW_ATTRIBUTE"`
}

// AdjustAttributeResponse is the KMIP 2.0 Adjust Attribute response payload.
type AdjustAttributeResponse struct {
	UniqueIdentifier string `kmip:"UNIQUE_IDENTIFIER,required"`
}
