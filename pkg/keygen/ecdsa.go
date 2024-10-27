package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// GenerateKey generates a new ECDSA private key for the specified curve.
func generateECDSAKey(c elliptic.Curve) (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa.GenerateKey: %w", err)
	}
	return privateKey, nil
}

// generateECDSAKeys generates an ECDSA private and public key pair.
func createRootCertificate(key *ecdsa.PrivateKey) (*x509.Certificate, error) {
	// Create a rootTemplate for the certificate with owner and issuer information
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Root Common Name",
			Organization: []string{"Root Organisation Name"},
			Country:      []string{"Country"},
		},
		Issuer: pkix.Name{
			CommonName:   "Root Common Name",
			Organization: []string{"Root Organisation Name"},
			Country:      []string{"Country"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0), // Valid for 5 years
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
	}

	// Self-sign the Root Certificate
	certDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate for easier handling later
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

func createLeafCertificate(parentCert *x509.Certificate, leafPub *ecdsa.PublicKey, signerKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	// Create a leafTemplate for the certificate with owner and issuer information
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Leaf Common Name",
			Organization: []string{"Leaf Organisation Name"},
			Country:      []string{"Country"},
		},
		Issuer: pkix.Name{
			CommonName:   "Root Common Name",
			Organization: []string{"Root Organisation Name"},
			Country:      []string{"Country"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(2, 0, 0), // Valid for 2 years
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageCodeSigning,
			x509.ExtKeyUsageEmailProtection,
		},
		BasicConstraintsValid: true,
	}

	// Sign the Leaf Certificate
	certDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, parentCert, leafPub, signerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate for easier handling later
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// savePrivateKeyToPEM saves an ECDSA private key to a PEM file.
func savePrivateKeyToPEM(privateKey *ecdsa.PrivateKey, privateKeyPath string) error {
	// Marshal the private key into ASN.1 DER-encoded form
	der, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("x509.MarshalECPrivateKey: %w", err)
	}

	// Create a PEM block with the encoded private key
	privateKeyPEM := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}

	// Write the private key to a PEM file
	file, err := os.Create(privateKeyPath)
	if err != nil {
		return fmt.Errorf("os.Create: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, &privateKeyPEM); err != nil {
		return fmt.Errorf("pem.Encode: %w", err)
	}
	return nil
}

// savePublicKeyToPEM saves an ECDSA public key to a PEM file.
func savePublicKeyToPEM(publicKey *ecdsa.PublicKey, publicKeyPath string) error {
	// Marshal the public key into ASN.1 DER-encoded form
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("x509.MarshalPKIXPublicKey: %w", err)
	}

	// Create a PEM block with the encoded public key
	publicKeyPEM := pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: der,
	}

	// Write the public key to a PEM file
	file, err := os.Create(publicKeyPath)
	if err != nil {
		return fmt.Errorf("os.Create: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, &publicKeyPEM); err != nil {
		return fmt.Errorf("pem.Encode: %w", err)
	}
	return nil
}

// save
func saveCertificateToFile(cert *x509.Certificate, certPath string) error {
	// Create a PEM block with the encoded public key
	certPEM := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	// Write the public key to a PEM file
	file, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("os.Create: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, &certPEM); err != nil {
		return fmt.Errorf("pem.Encode: %w", err)
	}
	return nil
}

func GenerateKeys() {
	// Generate ECDSA private and public keys
	rootPrivateKey, err := generateECDSAKey(elliptic.P256())
	if err != nil {
		fmt.Fprintf(os.Stderr, "generateECDSAKeys: %v\n", err)
		return
	}

	// Create ROOT certificate for the privateKey
	rootCert, err := createRootCertificate(rootPrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "createRootCertificate: %v\n", err)
	}

	// Generate ECDSA private and public keys
	leafPrivateKey, err := generateECDSAKey(elliptic.P256())
	if err != nil {
		fmt.Fprintf(os.Stderr, "generateECDSAKeys: %v\n", err)
		return
	}

	// Create Leaf certificate for the privateKey
	leafCert, err := createLeafCertificate(rootCert, &leafPrivateKey.PublicKey, rootPrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "createLeafCertificate: %v\n", err)
	}

	// Save the private key to PEM file
	rootPrivateKeyPath := "root_private_ecdsa.pem"
	if err := savePrivateKeyToPEM(rootPrivateKey, rootPrivateKeyPath); err != nil {
		fmt.Fprintf(os.Stderr, "savePrivateKeyToPEM: %v\n", err)
		return
	}
	fmt.Printf("ECDSA private key saved to %q\n", rootPrivateKeyPath)

	// Save the public key to PEM file
	rootPublicKeyPath := "root_public_ecdsa.pem"
	if err := savePublicKeyToPEM(rootPrivateKey.Public().(*ecdsa.PublicKey), rootPublicKeyPath); err != nil {
		fmt.Fprintf(os.Stderr, "savePublicKeyToPEM: %v\n", err)
		return
	}
	fmt.Printf("ECDSA public key saved to %q\n", rootPublicKeyPath)

	// Save the certificate key to PEM file
	rootCertPath := "root_cert_ecdsa.pem"
	if err := saveCertificateToFile(rootCert, rootCertPath); err != nil {
		fmt.Fprintf(os.Stderr, "saveCertificateToFile: %v\n", err)
		return
	}
	fmt.Printf("ECDSA root certificate saved to %q\n", rootCertPath)

	// Save the private key to PEM file
	leafPrivateKeyPath := "leaf_private_ecdsa.pem"
	if err := savePrivateKeyToPEM(leafPrivateKey, leafPrivateKeyPath); err != nil {
		fmt.Fprintf(os.Stderr, "savePrivateKeyToPEM: %v\n", err)
		return
	}
	fmt.Printf("ECDSA private key saved to %q\n", leafPrivateKeyPath)

	// Save the public key to PEM file
	leafPublicKeyPath := "leaf_public_ecdsa.pem"
	if err := savePublicKeyToPEM(leafPrivateKey.Public().(*ecdsa.PublicKey), leafPublicKeyPath); err != nil {
		fmt.Fprintf(os.Stderr, "savePublicKeyToPEM: %v\n", err)
		return
	}
	fmt.Printf("ECDSA public key saved to %q\n", leafPublicKeyPath)

	// Save the certificate key to PEM file
	leafCertPath := "leaf_cert_ecdsa.pem"
	if err := saveCertificateToFile(leafCert, leafCertPath); err != nil {
		fmt.Fprintf(os.Stderr, "saveCertificateToFile: %v\n", err)
		return
	}
	fmt.Printf("ECDSA root certificate saved to %q\n", leafCertPath)
}
