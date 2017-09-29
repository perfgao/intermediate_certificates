package censys

import (
    "fmt"
)


func GetAllRoot() []byte {
    query_sql := "tags: root"
    query_data := Build_body_json(query_sql)
    if query_data == "" {
        fmt.Println("build query statement failed")
        return nil
    }

    fmt.Println("Query: ", query_data)

    reqoption := ReqOptions{
        method : "POST",
        suburl : "/search/certificates",
        bodyFlag : true,
        body : query_data,
    }

    return Request(reqoption)
}

func GetRootCert(sha256 string) {
    if sha256 == "" {
        return
    }

    reqoption := ReqOptions{
        method : "GET",
        suburl : "/view/certificates/" + sha256,
        bodyFlag : false,
    }

    result := Request(reqoption)

    certdetail := ParseCertDetail(result)

    cert := AdjustPemFormat(certdetail.Raw)
    fmt.Println(string(cert))
}
