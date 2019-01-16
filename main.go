package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// x509 template configurations
var country = flag.String("country", os.Getenv("CERT_COUNTRY"), "x509 country")
var locality = flag.String("locality", os.Getenv("CERT_LOCALITY"), "x509 locality")
var province = flag.String("province", os.Getenv("CERT_PROVINCE"), "x509 province")
var address = flag.String("address", os.Getenv("CERT_ADDR"), "x509 street address")
var postalCode = flag.String("postalcode", os.Getenv("CERT_POSTALCODE"), "x509 postal code")
var commonName = flag.String("commonname", os.Getenv("CERT_COMMONNAME"), "x509 common name")
var org = flag.String("org", os.Getenv("CERT_ORG"), "x509 organization")
var orgUnit = flag.String("orgunit", os.Getenv("CERT_ORGUNIT"), "x509 organizational unit")

// certificate file path
var caCertPath = flag.String("cacert", "cacert.pem", "ca certificate file path")
var caKeyPath = flag.String("cakey", "cakey.pem", "ca private key file path")
var serverCertPath = flag.String("servercert", "cert.pem", "server certificate file path")
var serverKeyPath = flag.String("serverkey", "key.pem", "server key file path")

// k8s configurations
var namespace = flag.String("namespace", os.Getenv("NAMESPACE"), "Kubernetes secret namespace")
var secretName = flag.String("secret", os.Getenv("SECRET_NAME"), "Kubernetes secret name")

// output configurations
var fileout = flag.Bool("fileout", false, "write certificate content to disk")
var secretout = flag.Bool("secretout", false, "write certificate content to Kubernetes secret")
var stdout = flag.Bool("stdout", true, "write certificate content to stdout")

// generateSecret creates Kubernetes secret
func generateSecret(data map[string][]byte) error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}
	secret, err := clientset.CoreV1().Secrets(*namespace).Create(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      *secretName,
			Namespace: *namespace,
		},
		Data: data,
		Type: v1.SecretTypeOpaque,
	})
	log.Printf("created secret: %+v", secret)
	return err
}

// generateFile creates certificate files
func generateFile(certFilePath, keyFilePath string, cert []byte, keyPair *rsa.PrivateKey) error {
	certOut, err := os.Create(certFilePath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	keyOut, err := os.OpenFile(keyFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if err != nil {
		return err
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keyPair)})
	if err != nil {
		return err
	}
	return nil
}

func main() {

	var err error

	caSerialNumber, err := rand.Int(rand.Reader, big.NewInt(9999))
	if err != nil {
		log.Fatalf("failed to generate random serial number: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: caSerialNumber,
		Subject: pkix.Name{
			Country:            []string{*country},
			Organization:       []string{*org},
			OrganizationalUnit: []string{*orgUnit},
			Locality:           []string{*locality},
			Province:           []string{*province},
			StreetAddress:      []string{*address},
			PostalCode:         []string{*postalCode},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(1 * time.Hour),
		IsCA:      true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// generate ca certificates
	log.Printf("generating ca certificates...")
	caKeyPair, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("failed to generat key pair: %v", err)
	}
	caCert, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKeyPair.PublicKey, caKeyPair)
	if err != nil {
		log.Fatalf("failed to create certificate: %v", err)
	}

	serverSerialNumber, err := rand.Int(rand.Reader, big.NewInt(9999))
	if err != nil {
		log.Fatalf("failed to generate random serial number: %v", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerialNumber,
		Subject: pkix.Name{
			Country:            []string{*country},
			Organization:       []string{*org},
			OrganizationalUnit: []string{*orgUnit},
			Locality:           []string{*locality},
			Province:           []string{*province},
			StreetAddress:      []string{*address},
			PostalCode:         []string{*postalCode},
			CommonName:         *commonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(1 * time.Hour),
		//SubjectKeyId: []byte{}, //TODO
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	// generate server certificates
	log.Printf("generating server certificates...")
	//x509.ParseCertificate()
	// ca, err := x509.ParseCertificates(
	// 	append(
	// 		x509.MarshalPKCS1PublicKey(&caKeyPair.PublicKey),
	// 		x509.MarshalPKCS1PrivateKey(caKeyPair)...,
	// 	),
	// )
	ca, err := x509.ParseCertificate(
		caCert,
	)
	if err != nil {
		log.Fatalf("failed to load ca certificates: %v", err)
	}
	keyPair, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("failed to generat key pair: %v", err)
	}
	cert, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &keyPair.PublicKey, keyPair)
	if err != nil {
		log.Fatalf("failed to create certificate: %v", err)
	}

	// verify
	caPool := x509.NewCertPool()
	ok := caPool.AppendCertsFromPEM(caCert)
	if !ok {
		log.Fatalf("failed to parse ca certificate")
	}
	serverCert, err := x509.ParseCertificate(cert)
	if err != nil {
		log.Fatalf("failed to parse server certificate: %v", err)
	}
	if _, err := serverCert.Verify(x509.VerifyOptions{
		Roots: caPool,
	}); err != nil {
		log.Fatalf("failed to verify certificate: %v", err)
	}

	if *stdout {
		b, _ := json.MarshalIndent(map[string][]byte{
			*caCertPath:     caCert,
			*serverCertPath: cert,
			*serverKeyPath:  x509.MarshalPKCS1PrivateKey(keyPair),
		}, "", "  ")
		log.Printf("generated certificates:\n%s", string(b))
	}

	if *fileout {
		log.Printf("writing certificates to file...")
		err = generateFile(*caCertPath, *caKeyPath, caCert, caKeyPair)
		if err != nil {
			log.Fatalf("failed to write ca certificate files to disk: %v", err)
		}
		err = generateFile(*serverCertPath, *serverKeyPath, cert, keyPair)
		if err != nil {
			log.Fatalf("failed to write server certificate files to disk: %v", err)
		}
	}

	if *secretout {
		log.Printf("create kubernetes secret...")
		err = generateSecret(map[string][]byte{
			*caCertPath:     caCert,
			*serverCertPath: cert,
			*serverKeyPath:  x509.MarshalPKCS1PrivateKey(keyPair),
		})
		if err != nil {
			log.Fatalf("failed to create kubernetes secret: %v", err)
		}
	}

	log.Printf("done")
}
