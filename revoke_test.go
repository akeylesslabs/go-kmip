package kmip

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeRevokeRequestUsesRevocationMessageTag(t *testing.T) {
	req := Request{
		Header: RequestHeader{
			Version:    ProtocolVersion{Major: 1, Minor: 4},
			BatchCount: 1,
		},
		BatchItems: []RequestBatchItem{
			{
				Operation: OPERATION_REVOKE,
				RequestPayload: RevokeRequest{
					UniqueIdentifier: "uid",
					RevocationReason: RevocationReason{
						RevocationReasonCode: REVOCATION_REASON_KEY_COMPROMISE,
						RevocationMessage:    "key compromised",
					},
					CompromiseOccurrenceDate: time.Unix(1717000000, 0),
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, NewEncoder(&buf).Encode(req))
	encoded := append([]byte(nil), buf.Bytes()...)

	var decoded Request
	require.NoError(t, NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, RevokeRequest{}, decoded.BatchItems[0].RequestPayload)
	revoke := decoded.BatchItems[0].RequestPayload.(RevokeRequest)
	require.Equal(t, "key compromised", revoke.RevocationReason.RevocationMessage)
	require.Equal(t, time.Unix(1717000000, 0), revoke.CompromiseOccurrenceDate)

	revocationMessageHeader := []byte{0x42, 0x00, 0x80, byte(TEXT_STRING)}
	compromiseOccurrenceDateHeader := []byte{0x42, 0x00, 0x21, byte(DATE_TIME)}
	require.True(t, bytes.Contains(encoded, revocationMessageHeader))
	require.True(t, bytes.Contains(encoded, compromiseOccurrenceDateHeader))
}

func TestDecodeRevokeRequestFallsBackToLegacyCompromiseDate(t *testing.T) {
	req := Request{
		Header: RequestHeader{
			Version:    ProtocolVersion{Major: 1, Minor: 4},
			BatchCount: 1,
		},
		BatchItems: []RequestBatchItem{
			{
				Operation: OPERATION_REVOKE,
				RequestPayload: legacyRevokeRequest{
					UniqueIdentifier: "uid",
					RevocationReason: RevocationReason{
						RevocationReasonCode: REVOCATION_REASON_KEY_COMPROMISE,
					},
					CompromiseDate: time.Unix(1717000000, 0),
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, NewEncoder(&buf).Encode(req))

	var decoded Request
	require.NoError(t, NewDecoder(&buf).Decode(&decoded))
	require.Len(t, decoded.BatchItems, 1)
	require.IsType(t, RevokeRequest{}, decoded.BatchItems[0].RequestPayload)
	revoke := decoded.BatchItems[0].RequestPayload.(RevokeRequest)
	require.Equal(t, time.Unix(1717000000, 0), revoke.CompromiseOccurrenceDate)
	require.Equal(t, time.Unix(1717000000, 0), revoke.CompromiseDate)
}

type legacyRevokeRequest struct {
	Tag `kmip:"REQUEST_PAYLOAD"`

	UniqueIdentifier string           `kmip:"UNIQUE_IDENTIFIER"`
	RevocationReason RevocationReason `kmip:"REVOCATION_REASON,required"`
	CompromiseDate   time.Time        `kmip:"COMPROMISE_DATE"`
}
