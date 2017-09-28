package censys

import (
    "encoding/json"
    "fmt"
    "os"
    "io"
    "strings"
)

type AllData struct {
    Raw string `json:"raw"`
}

func WritePEMFile(data []byte, filename string) {
    var alldata AllData

    json.Unmarshal(data, &alldata)

    //fmt.Println("Raw: ", alldata.Raw)
    output, err := os.Create(filename)
    if err != nil {
        fmt.Println(err)
        return
    }
    defer output.Close()

    r := strings.NewReader(alldata.Raw)

    io.WriteString(output, "-----BEGIN CERTIFICATE-----")
    for {
        io.WriteString(output, "\r\n")
        num, err := io.CopyN(output, r, 64)
        if err != nil {
            fmt.Println(err)
            break
        }

        if num == 0 {
            break
        }
    }
    io.WriteString(output, "\r\n-----END CERTIFICATE-----")
}

