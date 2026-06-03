package kmip

type AfterUnmarshalKMIP interface {
	AfterUnmarshalKMIP()
}

type AfterUnmarshalKMIPWithSeenFields interface {
	AfterUnmarshalKMIPWithSeenFields(map[string]bool)
}
