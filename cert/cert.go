package cert

import (
    "bytes"
)

func AdjustPemFormat(data string) []byte {
    var outbuf bytes.Buffer

    start, last := 0, 64
    dataLen := len(data)
    outbuf.WriteString("-----BEGIN CERTIFICATE-----\n")
    for {
        if last > dataLen {
            last = dataLen
        }

        tmp := data[start:last]
        if len(tmp) <= 0 {
            break
        }

        outbuf.WriteString(tmp)
        outbuf.WriteString("\n")
        if len(tmp) < 64 {
            break
        }

        start = last
        last += 65
    }
    outbuf.WriteString("-----END CERTIFICATE-----")

    return outbuf.Bytes()
}
