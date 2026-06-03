package kmip

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// topLegacyHook implements only the legacy hook.
type topLegacyHook struct {
	Tag `kmip:"COMPROMISE_DATE"`

	A      int32 `kmip:"ARCHIVE_DATE"`
	called bool  `kmip:"-"`
}

func (t *topLegacyHook) AfterUnmarshalKMIP() {
	t.called = true
}

func TestTopLevelLegacyHookFallback(t *testing.T) {
	orig := topLegacyHook{A: 123}

	var buf bytes.Buffer
	require.NoError(t, NewEncoder(&buf).Encode(&orig))

	var decoded topLegacyHook
	require.NoError(t, NewDecoder(&buf).Decode(&decoded))

	require.True(t, decoded.called, "expected legacy AfterUnmarshalKMIP to be invoked at top-level")
	require.Equal(t, int32(123), decoded.A)
}

