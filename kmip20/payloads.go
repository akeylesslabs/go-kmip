package kmip20

import (
	"strings"
	"time"

	"github.com/akeylesslabs/go-kmip"
	"github.com/pkg/errors"
)

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
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_ACTIVATE, func() interface{} {
		return &kmip.ActivateRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_GET_ATTRIBUTES, func() interface{} {
		return &GetAttributesRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_GET_ATTRIBUTE_LIST, func() interface{} {
		return &GetAttributeListRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_ENCRYPT, func() interface{} {
		return &EncryptRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_DECRYPT, func() interface{} {
		return &DecryptRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_REGISTER, func() interface{} {
		return &RegisterRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_LOCATE, func() interface{} {
		return &LocateRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_REKEY, func() interface{} {
		return &ReKeyRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_REVOKE, func() interface{} {
		return &RevokeRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_ADD_ATTRIBUTE, func() interface{} {
		return &AddAttributeRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_MODIFY_ATTRIBUTE, func() interface{} {
		return &ModifyAttributeRequest{}
	})
	kmip.RegisterRequestPayloadFactory(ProtocolVersion, kmip.OPERATION_DELETE_ATTRIBUTE, func() interface{} {
		return &DeleteAttributeRequest{}
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
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_ACTIVATE, func() interface{} {
		return &kmip.ActivateResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_GET_ATTRIBUTES, func() interface{} {
		return &GetAttributesResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_GET_ATTRIBUTE_LIST, func() interface{} {
		return &GetAttributeListResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_ENCRYPT, func() interface{} {
		return &kmip.EncryptResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_DECRYPT, func() interface{} {
		return &kmip.DecryptResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_REGISTER, func() interface{} {
		return &RegisterResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_LOCATE, func() interface{} {
		return &LocateResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_REKEY, func() interface{} {
		return &ReKeyResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_REVOKE, func() interface{} {
		return &RevokeResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_ADD_ATTRIBUTE, func() interface{} {
		return &AddAttributeResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_MODIFY_ATTRIBUTE, func() interface{} {
		return &ModifyAttributeResponse{}
	})
	kmip.RegisterResponsePayloadFactory(ProtocolVersion, kmip.OPERATION_DELETE_ATTRIBUTE, func() interface{} {
		return &DeleteAttributeResponse{}
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

	Name                   kmip.Name `kmip:"NAME"`
	ObjectType             kmip.Enum `kmip:"OBJECT_TYPE"`
	CryptographicAlgorithm kmip.Enum `kmip:"CRYPTOGRAPHIC_ALGORITHM"`
	CryptographicLength    int32     `kmip:"CRYPTOGRAPHIC_LENGTH"`
	CryptographicUsageMask int32     `kmip:"CRYPTOGRAPHIC_USAGE_MASK"`
	Sensitive              bool      `kmip:"SENSITIVE"`
	AlwaysSensitive        bool      `kmip:"ALWAYS_SENSITIVE"`
	Extractable            bool      `kmip:"EXTRACTABLE"`
	NeverExtractable       bool      `kmip:"NEVER_EXTRACTABLE"`
	ReplaceExisting        bool      `kmip:"REPLACE_EXISTING"`

	AttributeName  string      `kmip:"ATTRIBUTE_NAME"`
	AttributeIndex int32       `kmip:"ATTRIBUTE_INDEX"`
	AttributeValue interface{} `kmip:"ATTRIBUTE_VALUE"`

	NewAttributes     []Attributes `kmip:"NEW_ATTRIBUTE"`
	CurrentAttributes []Attributes `kmip:"CURRENT_ATTRIBUTE"`
}

// AttributeValues is the KMIP 2.0 Attributes response structure. It emits
// standard attributes as direct tags under ATTRIBUTES, not as legacy ATTRIBUTE
// wrappers.
type AttributeValues struct {
	kmip.Tag `kmip:"ATTRIBUTES"`

	Values kmip.Attributes

	UniqueIdentifier         *string    `kmip:"UNIQUE_IDENTIFIER"`
	Name                     *kmip.Name `kmip:"NAME"`
	ObjectType               *kmip.Enum `kmip:"OBJECT_TYPE"`
	CryptographicAlgorithm   *kmip.Enum `kmip:"CRYPTOGRAPHIC_ALGORITHM"`
	CryptographicLength      *int32     `kmip:"CRYPTOGRAPHIC_LENGTH"`
	CryptographicUsageMask   *int32     `kmip:"CRYPTOGRAPHIC_USAGE_MASK"`
	State                    *kmip.Enum `kmip:"STATE"`
	InitialDate              *time.Time `kmip:"INITIAL_DATE"`
	ActivationDate           *time.Time `kmip:"ACTIVATION_DATE"`
	ProcessStartDate         *time.Time `kmip:"PROCESS_START_DATE"`
	ProtectStopDate          *time.Time `kmip:"PROTECT_STOP_DATE"`
	DeactivationDate         *time.Time `kmip:"DEACTIVATION_DATE"`
	DestroyDate              *time.Time `kmip:"DESTROY_DATE"`
	CompromiseOccurrenceDate *time.Time `kmip:"COMPROMISE_OCCURRENCE_DATE"`
	CompromiseDate           *time.Time `kmip:"COMPROMISE_DATE"`
	ArchiveDate              *time.Time `kmip:"ARCHIVE_DATE"`
	LastChangeDate           *time.Time `kmip:"LAST_CHANGE_DATE"`
	OriginalCreationDate     *time.Time `kmip:"ORIGINAL_CREATION_DATE"`
	Sensitive                *bool      `kmip:"SENSITIVE"`
	AlwaysSensitive          *bool      `kmip:"ALWAYS_SENSITIVE"`
	Extractable              *bool      `kmip:"EXTRACTABLE"`
	NeverExtractable         *bool      `kmip:"NEVER_EXTRACTABLE"`
	ReplaceExisting          *bool      `kmip:"REPLACE_EXISTING"`
	Link                     *kmip.Link `kmip:"LINK"`
}

func (a *Attributes) AfterUnmarshalKMIP() {
	a.AfterUnmarshalKMIPWithSeenFields(nil)
}

func (a *Attributes) AfterUnmarshalKMIPWithSeenFields(seen map[string]bool) {
	for _, attr := range a.NewAttributes {
		if v := attr.Attribute(); v.Name != "" {
			a.Values = append(a.Values, v)
		}
	}
	for _, attr := range a.CurrentAttributes {
		if v := attr.Attribute(); v.Name != "" {
			a.Values = append(a.Values, v)
		}
	}
	if len(a.Values) == 0 && (seenField(seen, "AttributeName") || a.AttributeName != "") {
		a.Values = append(a.Values, kmip.Attribute{
			Name:  a.AttributeName,
			Index: a.AttributeIndex,
			Value: a.AttributeValue,
		})
	}
	if seenField(seen, "Name") || a.Name.Value != "" {
		a.Values = append(a.Values, kmip.Attribute{
			Name:  kmip.ATTRIBUTE_NAME_NAME,
			Value: a.Name,
		})
	}
	if seenField(seen, "ObjectType") || a.ObjectType != 0 {
		a.Values = append(a.Values, kmip.Attribute{
			Name:  kmip.ATTRIBUTE_NAME_OBJECT_TYPE,
			Value: a.ObjectType,
		})
	}
	if seenField(seen, "CryptographicAlgorithm") || a.CryptographicAlgorithm != 0 {
		a.Values = append(a.Values, kmip.Attribute{
			Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM,
			Value: a.CryptographicAlgorithm,
		})
	}
	if seenField(seen, "CryptographicLength") || a.CryptographicLength != 0 {
		a.Values = append(a.Values, kmip.Attribute{
			Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH,
			Value: a.CryptographicLength,
		})
	}
	if seenField(seen, "CryptographicUsageMask") || a.CryptographicUsageMask != 0 {
		a.Values = append(a.Values, kmip.Attribute{
			Name:  kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK,
			Value: a.CryptographicUsageMask,
		})
	}
	if seenField(seen, "Sensitive") || a.Sensitive {
		a.Values = append(a.Values, kmip.Attribute{
			Name:  kmip.ATTRIBUTE_NAME_SENSITIVE,
			Value: a.Sensitive,
		})
	}
	if seenField(seen, "AlwaysSensitive") || a.AlwaysSensitive {
		a.Values = append(a.Values, kmip.Attribute{
			Name:  kmip.ATTRIBUTE_NAME_ALWAYS_SENSITIVE,
			Value: a.AlwaysSensitive,
		})
	}
	if seenField(seen, "Extractable") || a.Extractable {
		a.Values = append(a.Values, kmip.Attribute{
			Name:  kmip.ATTRIBUTE_NAME_EXTRACTABLE,
			Value: a.Extractable,
		})
	}
	if seenField(seen, "NeverExtractable") || a.NeverExtractable {
		a.Values = append(a.Values, kmip.Attribute{
			Name:  kmip.ATTRIBUTE_NAME_NEVER_EXTRACTABLE,
			Value: a.NeverExtractable,
		})
	}
	if seenField(seen, "ReplaceExisting") || a.ReplaceExisting {
		a.Values = append(a.Values, kmip.Attribute{
			Name:  kmip.ATTRIBUTE_NAME_REPLACE_EXISTING,
			Value: a.ReplaceExisting,
		})
	}
}

func seenField(seen map[string]bool, name string) bool {
	if seen == nil {
		return false
	}
	return seen[name]
}

func NewAttributeValues(attrs kmip.Attributes) AttributeValues {
	values := AttributeValues{}
	for _, attr := range attrs {
		values.Set(attr)
	}
	return values
}

func (a *AttributeValues) Set(attr kmip.Attribute) {
	a.Values = append(a.Values, attr)

	switch attr.Name {
	case kmip.ATTRIBUTE_NAME_UNIQUE_IDENTIFIER:
		if v, ok := attr.Value.(string); ok {
			a.UniqueIdentifier = &v
		}
	case kmip.ATTRIBUTE_NAME_NAME:
		if v, ok := attr.Value.(kmip.Name); ok {
			a.Name = &v
		}
	case kmip.ATTRIBUTE_NAME_OBJECT_TYPE:
		if v, ok := attr.Value.(kmip.Enum); ok {
			a.ObjectType = &v
		}
	case kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM:
		if v, ok := attr.Value.(kmip.Enum); ok {
			a.CryptographicAlgorithm = &v
		}
	case kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH:
		if v, ok := attr.Value.(int32); ok {
			a.CryptographicLength = &v
		}
	case kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK:
		if v, ok := attr.Value.(int32); ok {
			a.CryptographicUsageMask = &v
		}
	case kmip.ATTRIBUTE_NAME_STATE:
		if v, ok := attr.Value.(kmip.Enum); ok {
			a.State = &v
		}
	case kmip.ATTRIBUTE_NAME_INITIAL_DATE:
		if v, ok := attr.Value.(time.Time); ok {
			a.InitialDate = &v
		}
	case kmip.ATTRIBUTE_NAME_ACTIVATION_DATE:
		if v, ok := attr.Value.(time.Time); ok {
			a.ActivationDate = &v
		}
	case kmip.ATTRIBUTE_NAME_PROCESS_START_DATE:
		if v, ok := attr.Value.(time.Time); ok {
			a.ProcessStartDate = &v
		}
	case kmip.ATTRIBUTE_NAME_PROTECT_STOP_DATE:
		if v, ok := attr.Value.(time.Time); ok {
			a.ProtectStopDate = &v
		}
	case kmip.ATTRIBUTE_NAME_DEACTIVATION_DATE:
		if v, ok := attr.Value.(time.Time); ok {
			a.DeactivationDate = &v
		}
	case kmip.ATTRIBUTE_NAME_DESTROY_DATE:
		if v, ok := attr.Value.(time.Time); ok {
			a.DestroyDate = &v
		}
	case kmip.ATTRIBUTE_NAME_COMPROMISE_OCCURRENCE_DATE:
		if v, ok := attr.Value.(time.Time); ok {
			a.CompromiseOccurrenceDate = &v
		}
	case kmip.ATTRIBUTE_NAME_COMPROMISE_DATE:
		if v, ok := attr.Value.(time.Time); ok {
			a.CompromiseDate = &v
		}
	case kmip.ATTRIBUTE_NAME_ARCHIVE_DATE:
		if v, ok := attr.Value.(time.Time); ok {
			a.ArchiveDate = &v
		}
	case kmip.ATTRIBUTE_NAME_LAST_CHANGE_DATE:
		if v, ok := attr.Value.(time.Time); ok {
			a.LastChangeDate = &v
		}
	case kmip.ATTRIBUTE_NAME_ORIGINAL_CREATION_DATE:
		if v, ok := attr.Value.(time.Time); ok {
			a.OriginalCreationDate = &v
		}
	case kmip.ATTRIBUTE_NAME_SENSITIVE:
		if v, ok := attr.Value.(bool); ok {
			a.Sensitive = &v
		}
	case kmip.ATTRIBUTE_NAME_ALWAYS_SENSITIVE:
		if v, ok := attr.Value.(bool); ok {
			a.AlwaysSensitive = &v
		}
	case kmip.ATTRIBUTE_NAME_EXTRACTABLE:
		if v, ok := attr.Value.(bool); ok {
			a.Extractable = &v
		}
	case kmip.ATTRIBUTE_NAME_NEVER_EXTRACTABLE:
		if v, ok := attr.Value.(bool); ok {
			a.NeverExtractable = &v
		}
	case kmip.ATTRIBUTE_NAME_REPLACE_EXISTING:
		if v, ok := attr.Value.(bool); ok {
			a.ReplaceExisting = &v
		}
	case kmip.ATTRIBUTE_NAME_LINK:
		if v, ok := attr.Value.(kmip.Link); ok {
			a.Link = &v
		}
	}
}

func (a *AttributeValues) AfterUnmarshalKMIPWithSeenFields(seen map[string]bool) {
	if seenField(seen, "UniqueIdentifier") && a.UniqueIdentifier != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_UNIQUE_IDENTIFIER, Value: *a.UniqueIdentifier})
	}
	if seenField(seen, "Name") && a.Name != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_NAME, Value: *a.Name})
	}
	if seenField(seen, "ObjectType") && a.ObjectType != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_OBJECT_TYPE, Value: *a.ObjectType})
	}
	if seenField(seen, "CryptographicAlgorithm") && a.CryptographicAlgorithm != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM, Value: *a.CryptographicAlgorithm})
	}
	if seenField(seen, "CryptographicLength") && a.CryptographicLength != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH, Value: *a.CryptographicLength})
	}
	if seenField(seen, "CryptographicUsageMask") && a.CryptographicUsageMask != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK, Value: *a.CryptographicUsageMask})
	}
	if seenField(seen, "State") && a.State != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_STATE, Value: *a.State})
	}
	if seenField(seen, "InitialDate") && a.InitialDate != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_INITIAL_DATE, Value: *a.InitialDate})
	}
	if seenField(seen, "ActivationDate") && a.ActivationDate != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_ACTIVATION_DATE, Value: *a.ActivationDate})
	}
	if seenField(seen, "ProcessStartDate") && a.ProcessStartDate != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_PROCESS_START_DATE, Value: *a.ProcessStartDate})
	}
	if seenField(seen, "ProtectStopDate") && a.ProtectStopDate != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_PROTECT_STOP_DATE, Value: *a.ProtectStopDate})
	}
	if seenField(seen, "DeactivationDate") && a.DeactivationDate != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_DEACTIVATION_DATE, Value: *a.DeactivationDate})
	}
	if seenField(seen, "DestroyDate") && a.DestroyDate != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_DESTROY_DATE, Value: *a.DestroyDate})
	}
	if seenField(seen, "CompromiseOccurrenceDate") && a.CompromiseOccurrenceDate != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_COMPROMISE_OCCURRENCE_DATE, Value: *a.CompromiseOccurrenceDate})
	}
	if seenField(seen, "CompromiseDate") && a.CompromiseDate != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_COMPROMISE_DATE, Value: *a.CompromiseDate})
	}
	if seenField(seen, "ArchiveDate") && a.ArchiveDate != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_ARCHIVE_DATE, Value: *a.ArchiveDate})
	}
	if seenField(seen, "LastChangeDate") && a.LastChangeDate != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_LAST_CHANGE_DATE, Value: *a.LastChangeDate})
	}
	if seenField(seen, "OriginalCreationDate") && a.OriginalCreationDate != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_ORIGINAL_CREATION_DATE, Value: *a.OriginalCreationDate})
	}
	if seenField(seen, "Sensitive") && a.Sensitive != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_SENSITIVE, Value: *a.Sensitive})
	}
	if seenField(seen, "AlwaysSensitive") && a.AlwaysSensitive != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_ALWAYS_SENSITIVE, Value: *a.AlwaysSensitive})
	}
	if seenField(seen, "Extractable") && a.Extractable != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_EXTRACTABLE, Value: *a.Extractable})
	}
	if seenField(seen, "NeverExtractable") && a.NeverExtractable != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_NEVER_EXTRACTABLE, Value: *a.NeverExtractable})
	}
	if seenField(seen, "ReplaceExisting") && a.ReplaceExisting != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_REPLACE_EXISTING, Value: *a.ReplaceExisting})
	}
	if seenField(seen, "Link") && a.Link != nil {
		a.Values = append(a.Values, kmip.Attribute{Name: kmip.ATTRIBUTE_NAME_LINK, Value: *a.Link})
	}
}

func (a *Attributes) BuildFieldValue(name string) (interface{}, error) {
	if name != "AttributeValue" {
		return nil, errors.Errorf("unsupported dynamic field: %s", name)
	}

	return attributeValueByName(a.AttributeName)
}

func (a Attributes) Attribute() kmip.Attribute {
	if len(a.Values) == 0 {
		return kmip.Attribute{}
	}

	return a.Values[0]
}

func attributeValueByName(name string) (interface{}, error) {
	switch name {
	case kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM:
		return kmip.Enum(0), nil
	case kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH, kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK:
		return int32(0), nil
	case kmip.ATTRIBUTE_NAME_UNIQUE_IDENTIFIER, kmip.ATTRIBUTE_NAME_OPERATION_POLICY_NAME:
		return "", nil
	case kmip.ATTRIBUTE_NAME_OBJECT_TYPE, kmip.ATTRIBUTE_NAME_STATE:
		return kmip.Enum(0), nil
	case kmip.ATTRIBUTE_NAME_SENSITIVE, kmip.ATTRIBUTE_NAME_ALWAYS_SENSITIVE, kmip.ATTRIBUTE_NAME_EXTRACTABLE, kmip.ATTRIBUTE_NAME_NEVER_EXTRACTABLE, kmip.ATTRIBUTE_NAME_REPLACE_EXISTING:
		return false, nil
	case kmip.ATTRIBUTE_NAME_INITIAL_DATE, kmip.ATTRIBUTE_NAME_LAST_CHANGE_DATE, kmip.ATTRIBUTE_NAME_ACTIVATION_DATE, kmip.ATTRIBUTE_NAME_DEACTIVATION_DATE:
		return time.Time{}, nil
	case kmip.ATTRIBUTE_NAME_NAME:
		return &kmip.Name{}, nil
	case kmip.ATTRIBUTE_NAME_DIGEST:
		return &kmip.Digest{}, nil
	case kmip.ATTRIBUTE_NAME_LINK:
		return &kmip.Link{}, nil
	default:
		if strings.HasPrefix(name, "x-") || strings.HasPrefix(name, "y-") {
			return "", nil
		}
		return nil, errors.Errorf("unsupported attribute: %v", name)
	}
}

// CreateRequest is the KMIP 2.0 Create request payload.
type CreateRequest struct {
	ObjectType             kmip.Enum  `kmip:"OBJECT_TYPE,required"`
	Attributes             Attributes `kmip:"ATTRIBUTES"`
	ProtectionStorageMasks kmip.Enum  `kmip:"PROTECTION_STORAGE_MASKS"`

	TemplateAttribute kmip.TemplateAttribute `kmip:"TEMPLATE_ATTRIBUTE"`
}

func (r *CreateRequest) AfterUnmarshalKMIP() {
	if len(r.Attributes.Values) == 0 {
		r.Attributes.Values = r.TemplateAttribute.Attributes
	}
}

// CreateResponse is the KMIP 2.0 Create response payload.
type CreateResponse struct {
	ObjectType       kmip.Enum `kmip:"OBJECT_TYPE,required"`
	UniqueIdentifier string    `kmip:"UNIQUE_IDENTIFIER,required"`
}

// GetAttributesRequest is the KMIP 2.0 Get Attributes request payload.
type GetAttributesRequest struct {
	UniqueIdentifier       string               `kmip:"UNIQUE_IDENTIFIER"`
	AttributeReferenceTags []kmip.Enum          `kmip:"ATTRIBUTE_REFERENCE"`
	AttributeReferences    []AttributeReference `kmip:"ATTRIBUTE_REFERENCE"`
	AttributeNames         []string             `kmip:"ATTRIBUTE_NAME"`
}

func (r *GetAttributesRequest) AfterUnmarshalKMIP() {
	for _, name := range r.AttributeNames {
		if tag, ok := AttributeReferenceTag(name); ok {
			r.AttributeReferenceTags = append(r.AttributeReferenceTags, tag)
			continue
		}

		r.AttributeReferences = append(r.AttributeReferences, AttributeReference{Name: name})
	}
}

func (r GetAttributesRequest) AttributeReferenceNames() []string {
	names := make([]string, 0, len(r.AttributeReferenceTags)+len(r.AttributeReferences))
	for _, tag := range r.AttributeReferenceTags {
		if name, ok := AttributeReferenceName(tag); ok {
			names = append(names, name)
		}
	}
	for _, ref := range r.AttributeReferences {
		names = append(names, ref.Name)
	}

	return names
}

// GetAttributesResponse is the KMIP 2.0 Get Attributes response payload.
type GetAttributesResponse struct {
	UniqueIdentifier string          `kmip:"UNIQUE_IDENTIFIER,required"`
	Attributes       AttributeValues `kmip:"ATTRIBUTES,required"`
}

// GetAttributeListRequest is the KMIP 2.0 Get Attribute List request payload.
type GetAttributeListRequest struct {
	UniqueIdentifier string `kmip:"UNIQUE_IDENTIFIER"`
}

// GetAttributeListResponse is the KMIP 2.0 Get Attribute List response payload.
type GetAttributeListResponse struct {
	UniqueIdentifier    string      `kmip:"UNIQUE_IDENTIFIER,required"`
	AttributeReferences []kmip.Enum `kmip:"ATTRIBUTE_REFERENCE"`
}

// EncryptRequest is the KMIP 2.0 Encrypt request payload.
type EncryptRequest struct {
	UniqueIdentifier string            `kmip:"UNIQUE_IDENTIFIER"`
	CryptoParams     kmip.CryptoParams `kmip:"CRYPTOGRAPHIC_PARAMETERS"`
	Data             []byte            `kmip:"DATA"`
	IVCounterNonce   []byte            `kmip:"IV_COUNTER_NONCE"`
	CorrelationValue []byte            `kmip:"CORRELATION_VALUE"`
	InitIndicator    bool              `kmip:"INIT_INDICATOR"`
	FinalIndicator   bool              `kmip:"FINAL_INDICATOR"`
	AdditionalData   []byte            `kmip:"AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA"`
}

// DecryptRequest is the KMIP 2.0 Decrypt request payload.
type DecryptRequest struct {
	UniqueIdentifier string            `kmip:"UNIQUE_IDENTIFIER"`
	CryptoParams     kmip.CryptoParams `kmip:"CRYPTOGRAPHIC_PARAMETERS"`
	Data             []byte            `kmip:"DATA"`
	IVCounterNonce   []byte            `kmip:"IV_COUNTER_NONCE"`
	CorrelationValue []byte            `kmip:"CORRELATION_VALUE"`
	InitIndicator    bool              `kmip:"INIT_INDICATOR"`
	FinalIndicator   bool              `kmip:"FINAL_INDICATOR"`
	AdditionalData   []byte            `kmip:"AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA"`
	AuthTag          []byte            `kmip:"AUTHENTICATED_ENCRYPTION_TAG"`
}

// RevokeRequest is the KMIP 2.0 Revoke request payload.
type RevokeRequest struct {
	UniqueIdentifier         string                `kmip:"UNIQUE_IDENTIFIER"`
	RevocationReason         kmip.RevocationReason `kmip:"REVOCATION_REASON,required"`
	CompromiseOccurrenceDate time.Time             `kmip:"COMPROMISE_OCCURRENCE_DATE"`
	CompromiseDate           time.Time             `kmip:"COMPROMISE_DATE"`
}

func (r *RevokeRequest) AfterUnmarshalKMIP() {
	if r.CompromiseOccurrenceDate.IsZero() {
		r.CompromiseOccurrenceDate = r.CompromiseDate
	}
}

// RevokeResponse is the KMIP 2.0 Revoke response payload.
type RevokeResponse struct {
	UniqueIdentifier string `kmip:"UNIQUE_IDENTIFIER,required"`
}

// ReKeyRequest is the KMIP 2.0 Re-key request payload.
type ReKeyRequest struct {
	UniqueIdentifier       string        `kmip:"UNIQUE_IDENTIFIER"`
	Offset                 time.Duration `kmip:"OFFSET"`
	Attributes             Attributes    `kmip:"ATTRIBUTES"`
	ProtectionStorageMasks kmip.Enum     `kmip:"PROTECTION_STORAGE_MASKS"`

	TemplateAttribute kmip.TemplateAttribute `kmip:"TEMPLATE_ATTRIBUTE"`
}

func (r *ReKeyRequest) AfterUnmarshalKMIP() {
	if len(r.Attributes.Values) == 0 {
		r.Attributes.Values = r.TemplateAttribute.Attributes
	}
}

// ReKeyResponse is the KMIP 2.0 Re-key response payload.
type ReKeyResponse struct {
	UniqueIdentifier string `kmip:"UNIQUE_IDENTIFIER,required"`
}

// CreateKeyPairRequest is the KMIP 2.0 Create Key Pair request payload.
type CreateKeyPairRequest struct {
	CommonAttributes                 Attributes `kmip:"COMMON_ATTRIBUTES"`
	PrivateKeyAttributes             Attributes `kmip:"PRIVATE_KEY_ATTRIBUTES"`
	PublicKeyAttributes              Attributes `kmip:"PUBLIC_KEY_ATTRIBUTES"`
	CommonProtectionStorageMasks     kmip.Enum  `kmip:"PROTECTION_STORAGE_MASKS"`
	PrivateKeyProtectionStorageMasks kmip.Enum  `kmip:"PROTECTION_STORAGE_MASKS"`
	PublicKeyProtectionStorageMasks  kmip.Enum  `kmip:"PROTECTION_STORAGE_MASKS"`

	CommonTemplateAttribute     kmip.TemplateAttribute `kmip:"COMMON_TEMPLATE_ATTRIBUTE"`
	PrivateKeyTemplateAttribute kmip.TemplateAttribute `kmip:"PRIVATE_KEY_TEMPLATE_ATTRIBUTE"`
	PublicKeyTemplateAttribute  kmip.TemplateAttribute `kmip:"PUBLIC_KEY_TEMPLATE_ATTRIBUTE"`
}

func (r *CreateKeyPairRequest) AfterUnmarshalKMIP() {
	if len(r.CommonAttributes.Values) == 0 {
		r.CommonAttributes.Values = r.CommonTemplateAttribute.Attributes
	}
	if len(r.PrivateKeyAttributes.Values) == 0 {
		r.PrivateKeyAttributes.Values = r.PrivateKeyTemplateAttribute.Attributes
	}
	if len(r.PublicKeyAttributes.Values) == 0 {
		r.PublicKeyAttributes.Values = r.PublicKeyTemplateAttribute.Attributes
	}
}

// CreateKeyPairResponse is the KMIP 2.0 Create Key Pair response payload.
type CreateKeyPairResponse struct {
	PrivateKeyUniqueIdentifier string `kmip:"PRIVATE_KEY_UNIQUE_IDENTIFIER,required"`
	PublicKeyUniqueIdentifier  string `kmip:"PUBLIC_KEY_UNIQUE_IDENTIFIER,required"`
}

// RegisterRequest is the KMIP 2.0 Register request payload.
type RegisterRequest struct {
	ObjectType kmip.Enum  `kmip:"OBJECT_TYPE,required"`
	Attributes Attributes `kmip:"ATTRIBUTES"`

	SymmetricKey kmip.SymmetricKey `kmip:"SYMMETRIC_KEY"`
	PrivateKey   kmip.PrivateKey   `kmip:"PRIVATE_KEY"`
	PublicKey    kmip.PublicKey    `kmip:"PUBLIC_KEY"`
	Certificate  kmip.Certificate  `kmip:"CERTIFICATE"`
	OpaqueObject kmip.OpaqueObject `kmip:"OPAQUE_OBJECT"`

	TemplateAttribute kmip.TemplateAttribute `kmip:"TEMPLATE_ATTRIBUTE"`
}

func (r *RegisterRequest) AfterUnmarshalKMIP() {
	if len(r.Attributes.Values) == 0 {
		r.Attributes.Values = r.TemplateAttribute.Attributes
	}
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
	UniqueIdentifier string     `kmip:"UNIQUE_IDENTIFIER"`
	NewAttribute     Attributes `kmip:"NEW_ATTRIBUTE,required"`
}

// SetAttributeResponse is the KMIP 2.0 Set Attribute response payload.
type SetAttributeResponse struct {
	UniqueIdentifier string `kmip:"UNIQUE_IDENTIFIER,required"`
}

// AddAttributeRequest is the KMIP 2.0 Add Attribute request payload.
type AddAttributeRequest struct {
	UniqueIdentifier string       `kmip:"UNIQUE_IDENTIFIER"`
	NewAttribute     []Attributes `kmip:"NEW_ATTRIBUTE"`

	Attribute kmip.Attribute `kmip:"ATTRIBUTE"`
}

func (r *AddAttributeRequest) AfterUnmarshalKMIP() {
	if len(r.NewAttribute) == 0 && r.Attribute.Name != "" {
		r.NewAttribute = append(r.NewAttribute, Attributes{
			Values: kmip.Attributes{r.Attribute},
		})
	}
}

func (r AddAttributeRequest) AttributeValue() kmip.Attribute {
	if len(r.NewAttribute) == 0 {
		return kmip.Attribute{}
	}

	return r.NewAttribute[0].Attribute()
}

// AddAttributeResponse is the KMIP 2.0 Add Attribute response payload.
type AddAttributeResponse struct {
	UniqueIdentifier string `kmip:"UNIQUE_IDENTIFIER,required"`
}

// ModifyAttributeRequest is the KMIP 2.0 Modify Attribute request payload.
type ModifyAttributeRequest struct {
	UniqueIdentifier string     `kmip:"UNIQUE_IDENTIFIER"`
	CurrentAttribute Attributes `kmip:"CURRENT_ATTRIBUTE"`
	NewAttribute     Attributes `kmip:"NEW_ATTRIBUTE"`

	Attribute kmip.Attribute `kmip:"ATTRIBUTE"`
}

func (r *ModifyAttributeRequest) AfterUnmarshalKMIP() {
	if len(r.NewAttribute.Values) == 0 && r.Attribute.Name != "" {
		r.NewAttribute.Values = append(r.NewAttribute.Values, r.Attribute)
	}
}

func (r ModifyAttributeRequest) AttributeValue() kmip.Attribute {
	return r.NewAttribute.Attribute()
}

// ModifyAttributeResponse is the KMIP 2.0 Modify Attribute response payload.
type ModifyAttributeResponse struct {
	UniqueIdentifier string `kmip:"UNIQUE_IDENTIFIER,required"`
}

// DeleteAttributeRequest is the KMIP 2.0 Delete Attribute request payload.
type DeleteAttributeRequest struct {
	UniqueIdentifier       string               `kmip:"UNIQUE_IDENTIFIER"`
	CurrentAttribute       Attributes           `kmip:"CURRENT_ATTRIBUTE"`
	AttributeReferenceTags []kmip.Enum          `kmip:"ATTRIBUTE_REFERENCE"`
	AttributeReferences    []AttributeReference `kmip:"ATTRIBUTE_REFERENCE"`

	AttributeName  string  `kmip:"ATTRIBUTE_NAME"`
	AttributeIndex []int32 `kmip:"ATTRIBUTE_INDEX"`
}

func (r *DeleteAttributeRequest) AfterUnmarshalKMIP() {
	if r.AttributeName == "" {
		return
	}
	if tag, ok := AttributeReferenceTag(r.AttributeName); ok {
		r.AttributeReferenceTags = append(r.AttributeReferenceTags, tag)
		return
	}

	r.AttributeReferences = append(r.AttributeReferences, AttributeReference{Name: r.AttributeName})
}

func (r DeleteAttributeRequest) AttributeNameValue() string {
	if attr := r.CurrentAttribute.Attribute(); attr.Name != "" {
		return attr.Name
	}
	if len(r.AttributeReferenceTags) > 0 {
		if name, ok := AttributeReferenceName(r.AttributeReferenceTags[0]); ok {
			return name
		}
	}
	if len(r.AttributeReferences) > 0 {
		return r.AttributeReferences[0].Name
	}
	return ""
}

// DeleteAttributeResponse is the KMIP 2.0 Delete Attribute response payload.
type DeleteAttributeResponse struct {
	UniqueIdentifier string `kmip:"UNIQUE_IDENTIFIER,required"`
}

// AttributeReference is the KMIP 2.0 Attribute Reference structure.
type AttributeReference struct {
	kmip.Tag `kmip:"ATTRIBUTE_REFERENCE"`

	Name  string `kmip:"ATTRIBUTE_NAME,required"`
	Index int32  `kmip:"ATTRIBUTE_INDEX"`
}

var attributeReferenceTagsByName = map[string]kmip.Enum{
	kmip.ATTRIBUTE_NAME_UNIQUE_IDENTIFIER:                kmip.Enum(kmip.UNIQUE_IDENTIFIER),
	kmip.ATTRIBUTE_NAME_NAME:                             kmip.Enum(kmip.NAME),
	kmip.ATTRIBUTE_NAME_OBJECT_TYPE:                      kmip.Enum(kmip.OBJECT_TYPE),
	kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM:          kmip.Enum(kmip.CRYPTOGRAPHIC_ALGORITHM),
	kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH:             kmip.Enum(kmip.CRYPTOGRAPHIC_LENGTH),
	kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_PARAMETERS:         kmip.Enum(kmip.CRYPTOGRAPHIC_PARAMETERS),
	kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_DOMAIN_PARAMETERS:  kmip.Enum(kmip.CRYPTOGRAPHIC_DOMAIN_PARAMETERS),
	kmip.ATTRIBUTE_NAME_CERTIFICATE_TYPE:                 kmip.Enum(kmip.CERTIFICATE_TYPE),
	kmip.ATTRIBUTE_NAME_CERTIFICATE_LENGTH:               kmip.Enum(kmip.CERTIFICATE_LENGTH),
	kmip.ATTRIBUTE_NAME_X_509_CERTIFICATE_IDENTIFIER:     kmip.Enum(kmip.X_509_CERTIFICATE_IDENTIFIER),
	kmip.ATTRIBUTE_NAME_X_509_CERTIFICATE_SUBJECT:        kmip.Enum(kmip.X_509_CERTIFICATE_SUBJECT),
	kmip.ATTRIBUTE_NAME_X_509_CERTIFICATE_ISSUER:         kmip.Enum(kmip.X_509_CERTIFICATE_ISSUER),
	kmip.ATTRIBUTE_NAME_CERTIFICATE_IDENTIFIER:           kmip.Enum(kmip.CERTIFICATE_IDENTIFIER),
	kmip.ATTRIBUTE_NAME_CERTIFICATE_SUBJECT:              kmip.Enum(kmip.CERTIFICATE_SUBJECT),
	kmip.ATTRIBUTE_NAME_CERTIFICATE_ISSUER:               kmip.Enum(kmip.CERTIFICATE_ISSUER),
	kmip.ATTRIBUTE_NAME_DIGITAL_SIGNATURE_ALGORITHM:      kmip.Enum(kmip.DIGITAL_SIGNATURE_ALGORITHM),
	kmip.ATTRIBUTE_NAME_DIGEST:                           kmip.Enum(kmip.DIGEST),
	kmip.ATTRIBUTE_NAME_OPERATION_POLICY_NAME:            kmip.Enum(kmip.OPERATION_POLICY_NAME),
	kmip.ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK:         kmip.Enum(kmip.CRYPTOGRAPHIC_USAGE_MASK),
	kmip.ATTRIBUTE_NAME_LEASE_TIME:                       kmip.Enum(kmip.LEASE_TIME),
	kmip.ATTRIBUTE_NAME_USAGE_LIMITS:                     kmip.Enum(kmip.USAGE_LIMITS),
	kmip.ATTRIBUTE_NAME_STATE:                            kmip.Enum(kmip.STATE),
	kmip.ATTRIBUTE_NAME_INITIAL_DATE:                     kmip.Enum(kmip.INITIAL_DATE),
	kmip.ATTRIBUTE_NAME_ACTIVATION_DATE:                  kmip.Enum(kmip.ACTIVATION_DATE),
	kmip.ATTRIBUTE_NAME_PROCESS_START_DATE:               kmip.Enum(kmip.PROCESS_START_DATE),
	kmip.ATTRIBUTE_NAME_PROTECT_STOP_DATE:                kmip.Enum(kmip.PROTECT_STOP_DATE),
	kmip.ATTRIBUTE_NAME_DEACTIVATION_DATE:                kmip.Enum(kmip.DEACTIVATION_DATE),
	kmip.ATTRIBUTE_NAME_DESTROY_DATE:                     kmip.Enum(kmip.DESTROY_DATE),
	kmip.ATTRIBUTE_NAME_COMPROMISE_OCCURRENCE_DATE:       kmip.Enum(kmip.COMPROMISE_OCCURRENCE_DATE),
	kmip.ATTRIBUTE_NAME_COMPROMISE_DATE:                  kmip.Enum(kmip.COMPROMISE_DATE),
	kmip.ATTRIBUTE_NAME_REVOCATION_REASON:                kmip.Enum(kmip.REVOCATION_REASON),
	kmip.ATTRIBUTE_NAME_ARCHIVE_DATE:                     kmip.Enum(kmip.ARCHIVE_DATE),
	kmip.ATTRIBUTE_NAME_OBJECT_GROUP:                     kmip.Enum(kmip.OBJECT_GROUP),
	kmip.ATTRIBUTE_NAME_FRESH:                            kmip.Enum(kmip.FRESH),
	kmip.ATTRIBUTE_NAME_LINK:                             kmip.Enum(kmip.LINK),
	kmip.ATTRIBUTE_NAME_APPLICATION_SPECIFIC_INFORMATION: kmip.Enum(kmip.APPLICATION_SPECIFIC_INFORMATION),
	kmip.ATTRIBUTE_NAME_CONTACT_INFORMATION:              kmip.Enum(kmip.CONTACT_INFORMATION),
	kmip.ATTRIBUTE_NAME_LAST_CHANGE_DATE:                 kmip.Enum(kmip.LAST_CHANGE_DATE),
	kmip.ATTRIBUTE_NAME_CUSTOM_ATTRIBUTE:                 kmip.Enum(kmip.CUSTOM_ATTRIBUTE),
	kmip.ATTRIBUTE_NAME_ALTERNATIVE_NAME:                 kmip.Enum(kmip.ALTERNATIVE_NAME),
	kmip.ATTRIBUTE_NAME_KEY_VALUE_PRESENT:                kmip.Enum(kmip.KEY_VALUE_PRESENT),
	kmip.ATTRIBUTE_NAME_KEY_VALUE_LOCATION:               kmip.Enum(kmip.KEY_VALUE_LOCATION),
	kmip.ATTRIBUTE_NAME_ORIGINAL_CREATION_DATE:           kmip.Enum(kmip.ORIGINAL_CREATION_DATE),
	kmip.ATTRIBUTE_NAME_SENSITIVE:                        kmip.Enum(kmip.SENSITIVE),
	kmip.ATTRIBUTE_NAME_ALWAYS_SENSITIVE:                 kmip.Enum(kmip.ALWAYS_SENSITIVE),
	kmip.ATTRIBUTE_NAME_EXTRACTABLE:                      kmip.Enum(kmip.EXTRACTABLE),
	kmip.ATTRIBUTE_NAME_NEVER_EXTRACTABLE:                kmip.Enum(kmip.NEVER_EXTRACTABLE),
	kmip.ATTRIBUTE_NAME_REPLACE_EXISTING:                 kmip.Enum(kmip.REPLACE_EXISTING),
}

var attributeNamesByReferenceTag = func() map[kmip.Enum]string {
	names := make(map[kmip.Enum]string, len(attributeReferenceTagsByName))
	for name, tag := range attributeReferenceTagsByName {
		names[tag] = name
	}
	return names
}()

// AttributeReferenceTag returns the standard KMIP tag enumeration for an attribute name.
func AttributeReferenceTag(name string) (kmip.Enum, bool) {
	tag, ok := attributeReferenceTagsByName[name]
	return tag, ok
}

// AttributeReferenceName returns the canonical attribute name for a standard KMIP tag enumeration.
func AttributeReferenceName(tag kmip.Enum) (string, bool) {
	name, ok := attributeNamesByReferenceTag[tag]
	return name, ok
}

// AdjustAttributeRequest is the KMIP 2.0 Adjust Attribute request payload.
type AdjustAttributeRequest struct {
	UniqueIdentifier string             `kmip:"UNIQUE_IDENTIFIER"`
	AttributeRef     AttributeReference `kmip:"ATTRIBUTE_REFERENCE,required"`
	AdjustmentType   kmip.Enum          `kmip:"ADJUSTMENT_TYPE,required"`
	AdjustmentValue  int32              `kmip:"ADJUSTMENT_VALUE"`
	CurrentAttribute Attributes         `kmip:"CURRENT_ATTRIBUTE"`
	NewAttribute     Attributes         `kmip:"NEW_ATTRIBUTE"`
}

// AdjustAttributeResponse is the KMIP 2.0 Adjust Attribute response payload.
type AdjustAttributeResponse struct {
	UniqueIdentifier string `kmip:"UNIQUE_IDENTIFIER,required"`
}
