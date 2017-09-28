package censys

import (
    "fmt"
    "log"
    "io/ioutil"
    "encoding/json"
    "encoding/pem"
    "crypto/x509"
    "crypto/sha256"
    "encoding/hex"
)


func LoadPEM(path string) []byte {
    contnet, err := ioutil.ReadFile(path)
    if err != nil {
        fmt.Println(err)
        log.Fatal(err)
    }

    return contnet
}

func ParseCert(sslContent []byte) *x509.Certificate {
    pemBlock, _ := pem.Decode(sslContent)
    cert, err1 := x509.ParseCertificate(pemBlock.Bytes)
    if err1 != nil {
        log.Fatal(err1)
    }

    return cert
}

type CertificateFingerprint []byte

func GetSha256(cert *x509.Certificate) string {
    return hex.EncodeToString(Sha256Fingerprint(cert.Raw))
}

func Sha256Fingerprint(data []byte) CertificateFingerprint {
    sum := sha256.Sum256(data)

    return sum[:]
}

func ParseRoot() string {
    contnet := LoadPEM("/root/go/src/perfgao/censys_io/bin/root/1.pem")
    cert := ParseCert(contnet)

    sha256 := GetSha256(cert)
    fmt.Println(sha256)
    return sha256
}

type IMetadatas struct {
    Count int `json:"count"`
    Query string `json:"query"`
    BackendTime int `json:"backend_time"`
    Page int `json:"page"`
    Pages int `json:"pages"`
}

type IParseds struct {
    Sha256 string `json:"parsed.fingerprint_sha256"`
    SubjectDN string `json:"parsed.subject_dn"`
    IssuerDN string `json:"parsed.issuer_dn"`
}

type Intermediate struct {
    Status string `json:"status"`
    Metadata IMetadatas `json:"metadata"`
    Results []IParseds `json:"results"`
}

func ParseIntermediate(data []byte) {
    var intermediate Intermediate
    json.Unmarshal(data, &intermediate)

    fmt.Println(intermediate.Status, intermediate.Metadata.Count)

    if intermediate.Status != "ok" {
        fmt.Println("failed")
        return
    }

    if intermediate.Metadata.Count <= 0 {
        fmt.Println("get result count <= 0")
        return
    }

    for _, parsed := range intermediate.Results {
        fmt.Println(parsed.Sha256)
        respBody := View(parsed.Sha256)
        BuildInterCertName(respBody)
    }

}

type ICSubjects struct {
    CN []string `json:"common_name"`
}

type ICParseds struct {
    Sha256 string `json:"fingerprint_sha256"`
    Subject ICSubjects `json:"subject"`
}

type ICCcadb struct {
    CertName string `json:"certificate_name"`
}

type ICAudits struct {
    Ccadb ICCcadb `json:"ccadb"`
}

type IntermediateCert struct {
    Parsed ICParseds `json:"parsed"`
    Audit  ICAudits `json:"audit"`
}

func BuildInterCertName(data []byte) {
    var interCert IntermediateCert
    json.Unmarshal(data, &interCert)

    fmt.Println(interCert.Audit.Ccadb.CertName, interCert.Parsed.Sha256)

    cn := interCert.Audit.Ccadb.CertName
    if cn == "" {
        cn = interCert.Parsed.Subject.CN[0]
    }

    WritePEMFile(data, "./intermediate/" + cn + "_" + interCert.Parsed.Sha256)
}
