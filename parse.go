package censys

import (
    "fmt"
    "log"
    "encoding/json"
    "encoding/pem"
    "crypto/x509"
    "crypto/sha256"
    "encoding/hex"
)



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
    contnet := loadPEM("/root/go/src/perfgao/censys_io/bin/root/1.pem")
    cert := ParseCert(contnet)

    sha256 := GetSha256(cert)
    fmt.Println(sha256)
    return sha256
}

type Metadatas struct {
    Count int `json:"count"`
    Query string `json:"query"`
    BackendTime int `json:"backend_time"`
    Page int `json:"page"`
    Pages int `json:"pages"`
}

type Parseds struct {
    Sha256 string `json:"parsed.fingerprint_sha256"`
    SubjectDN string `json:"parsed.subject_dn"`
    IssuerDN string `json:"parsed.issuer_dn"`
}

type QueryList struct {
    Status string `json:"status"`
    Metadata Metadatas `json:"metadata"`
    Results []Parseds `json:"results"`
}

func ParseIntermediate(data []byte) *QueryList {
    var intermediate QueryList
    json.Unmarshal(data, &intermediate)

    fmt.Println(intermediate.Status, intermediate.Metadata.Count)

    if intermediate.Status != "ok" {
        fmt.Println("failed")
        return nil
    }

    if intermediate.Metadata.Count <= 0 {
        fmt.Println("get result count <= 0")
        return nil
    }

    return &intermediate
}


/**********************************************************/

type CDSubjects struct {
    CN []string `json:"common_name"`
}

type CDExtensions struct {
    SubjectKeyId string `json:"subject_key_id"`
}

type CDParseds struct {
    Sha256 string `json:"fingerprint_sha256"`
    Sha1 string `json:"fingerprint_sha1"`
    Md5 string `json:"fingerprint_md5"`
    Subject CDSubjects `json:"subject"`
    Extension CDExtensions `json:"extensions"`
    Validity CDValidity `json:"validity"`
    Issuer CDIssuer `json:"issuer"`
}

type CDIssuer struct {
    Cm []string `json:"common_name"`
    O []string `json:"organization"`
}

type CDValidity struct {
    Start string `json:"start"`
    End string `json:"end"`
}

type CDCcadb struct {
    CertName string `json:"certificate_name"`
}

type CDAudits struct {
    Ccadb CDCcadb `json:"ccadb"`
}

type CertDetails struct {
    Parsed CDParseds `json:"parsed"`
    Audit  CDAudits `json:"audit"`
    Tags   []string `json:"tags"`
    Raw string `json:"raw"`
}


func BuildCertName(certdetail CertDetails) string {
    cn := certdetail.Audit.Ccadb.CertName
    if cn == "" {
        cn = certdetail.Parsed.Subject.CN[0]
    }

    return cn + "_" + certdetail.Parsed.Sha256
    //WritePEMFile(data, "./intermediate/" + cn + "_" + certdetail.Parsed.Sha256)
}

func ParseCertDetail(data []byte) CertDetails {
    var certdetail CertDetails
    json.Unmarshal(data, &certdetail)

    return certdetail
}
