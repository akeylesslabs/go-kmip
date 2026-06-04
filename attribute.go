package kmip

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Attribute is a Attribute Object Structure
type Attribute struct {
	Tag `kmip:"ATTRIBUTE"`

	Name  string      `kmip:"ATTRIBUTE_NAME"`
	Index int32       `kmip:"ATTRIBUTE_INDEX"`
	Value interface{} `kmip:"ATTRIBUTE_VALUE"`

	// KMIP 2.0 attributes
	NameValue              Name  `kmip:"NAME"`
	ObjectType             Enum  `kmip:"OBJECT_TYPE"`
	CryptographicAlgorithm Enum  `kmip:"CRYPTOGRAPHIC_ALGORITHM"`
	CryptographicLength    int32 `kmip:"CRYPTOGRAPHIC_LENGTH"`
	CryptographicUsageMask int32 `kmip:"CRYPTOGRAPHIC_USAGE_MASK"`
	Sensitive              bool  `kmip:"SENSITIVE"`
	AlwaysSensitive        bool  `kmip:"ALWAYS_SENSITIVE"`
	Extractable            bool  `kmip:"EXTRACTABLE"`
	NeverExtractable       bool  `kmip:"NEVER_EXTRACTABLE"`
	ReplaceExisting        bool  `kmip:"REPLACE_EXISTING"`
}

// BuildFieldValue builds dynamic Value field
func (a *Attribute) BuildFieldValue(name string) (v interface{}, err error) {
	switch a.Name {
	case ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM:
		v = Enum(0)
	case ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH, ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK:
		v = int32(0)
	case ATTRIBUTE_NAME_UNIQUE_IDENTIFIER, ATTRIBUTE_NAME_OPERATION_POLICY_NAME:
		v = ""
	case ATTRIBUTE_NAME_OBJECT_TYPE, ATTRIBUTE_NAME_STATE:
		v = Enum(0)
	case ATTRIBUTE_NAME_SENSITIVE, ATTRIBUTE_NAME_ALWAYS_SENSITIVE, ATTRIBUTE_NAME_EXTRACTABLE, ATTRIBUTE_NAME_NEVER_EXTRACTABLE, ATTRIBUTE_NAME_REPLACE_EXISTING:
		v = false
	case ATTRIBUTE_NAME_INITIAL_DATE, ATTRIBUTE_NAME_LAST_CHANGE_DATE, ATTRIBUTE_NAME_ACTIVATION_DATE, ATTRIBUTE_NAME_DEACTIVATION_DATE:
		v = time.Time{}
	case ATTRIBUTE_NAME_NAME:
		v = &Name{}
	case ATTRIBUTE_NAME_DIGEST:
		v = &Digest{}
	case ATTRIBUTE_NAME_LINK:
		v = &Link{}
	default:
		if strings.HasPrefix(a.Name, "x-") || strings.HasPrefix(a.Name, "y-") {
			v = ""
		} else {
			err = errors.Errorf("unsupported attribute: %v", a.Name)
		}
	}

	return
}

func (a *Attribute) AfterUnmarshalKMIP() {
	if a.Name != "" {
		return
	}
	if a.NameValue.Value != "" {
		a.Name = ATTRIBUTE_NAME_NAME
		a.Value = a.NameValue
		return
	}
	if a.ObjectType != 0 {
		a.Name = ATTRIBUTE_NAME_OBJECT_TYPE
		a.Value = a.ObjectType
		return
	}
	if a.CryptographicAlgorithm != 0 {
		a.Name = ATTRIBUTE_NAME_CRYPTOGRAPHIC_ALGORITHM
		a.Value = a.CryptographicAlgorithm
		return
	}
	if a.CryptographicLength != 0 {
		a.Name = ATTRIBUTE_NAME_CRYPTOGRAPHIC_LENGTH
		a.Value = a.CryptographicLength
		return
	}
	if a.CryptographicUsageMask != 0 {
		a.Name = ATTRIBUTE_NAME_CRYPTOGRAPHIC_USAGE_MASK
		a.Value = a.CryptographicUsageMask
		return
	}
	if a.Sensitive {
		a.Name = ATTRIBUTE_NAME_SENSITIVE
		a.Value = a.Sensitive
		return
	}
	if a.AlwaysSensitive {
		a.Name = ATTRIBUTE_NAME_ALWAYS_SENSITIVE
		a.Value = a.AlwaysSensitive
		return
	}
	if a.Extractable {
		a.Name = ATTRIBUTE_NAME_EXTRACTABLE
		a.Value = a.Extractable
		return
	}
	if a.NeverExtractable {
		a.Name = ATTRIBUTE_NAME_NEVER_EXTRACTABLE
		a.Value = a.NeverExtractable
		return
	}
	if a.ReplaceExisting {
		a.Name = ATTRIBUTE_NAME_REPLACE_EXISTING
		a.Value = a.ReplaceExisting
	}
}

// Attributes is a sequence of Attribute objects which allows building and search
type Attributes []Attribute

func (attrs Attributes) Get(name string) (val interface{}) {
	for i := range attrs {
		if attrs[i].Name == name {
			val = attrs[i].Value
			break
		}
	}

	return
}

// TemplateAttribute is a Template-Attribute Object Structure
type TemplateAttribute struct {
	Tag `kmip:"TEMPLATE_ATTRIBUTE"`

	Name       Name       `kmip:"NAME"`
	Attributes Attributes `kmip:"ATTRIBUTE"`
}

// Name is a Name Attribute Structure
type Name struct {
	Tag `kmip:"NAME"`

	Value string `kmip:"NAME_VALUE,required"`
	Type  Enum   `kmip:"NAME_TYPE,required"`
}

// Digest is a Digest Attribute Structure
type Digest struct {
	Tag `kmip:"DIGEST"`

	HashingAlgorithm Enum   `kmip:"HASHING_ALGORITHM,required"`
	DigestValue      []byte `kmip:"DIGEST_VALUE"`
	KeyFormatType    Enum   `kmip:"KEY_FORMAT_TYPE"`
}

type Link struct {
	Type  Enum   `kmip:"LINK_TYPE,required"`
	Value string `kmip:"LINKED_OBJECT_IDENTIFIER,required"`
}
