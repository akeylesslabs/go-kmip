package kmip

type Certificate struct {
	Tag `kmip:"CERTIFICATE"`

	CertificateType  Enum   `kmip:"CERTIFICATE_TYPE,required"`
	CertificateValue string `kmip:"CERTIFICATE_VALUE,required"`
}
