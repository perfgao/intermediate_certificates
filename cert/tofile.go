package censys

import (
    "github.com/golang/glog"
    "os"
    "io"
    "io/ioutil"
    "strings"
)


func WritePEMFile(cert CertDetails, filename string) {

    output, err := os.Create(filename)
    if err != nil {
        glog.Error(err)
        return
    }
    defer output.Close()

    r := strings.NewReader(cert.Raw)

    output.WriteString("-----BEGIN CERTIFICATE-----")
    for {
        output.WriteString("\r\n")
        num, err := io.CopyN(output, r, 64)
        if err != nil {
            glog.Error(err)
            break
        }

        if num == 0 {
            break
        }
    }
    output.WriteString("\r\n-----END CERTIFICATE-----")
}

func loadPEM(path string) []byte {
    contnet, err := ioutil.ReadFile(path)
    if err != nil {
        glog.Fatal(err)
    }

    return contnet
}
