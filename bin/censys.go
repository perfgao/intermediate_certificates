package main

import (
    "fmt"
//    "flag"
    "perfgao/censys_io"
)


func main () {

    sha256 := censys.ParseRoot()
    fmt.Println(sha256)
    respBody := censys.View(sha256)
    //censys.WritePEMFile(string(respBody))
    subjectKeyId :=  censys.GetSubjectKeyId(respBody)
    info := censys.Search(subjectKeyId)
    censys.ParseIntermediate(info)
}
