package censys

import (
    "fmt"
    "time"
    "encoding/json"
)

type RootCert struct {
}

func (root *RootCert) Query(query_data string) []byte {
    return request(reqOptions{
        method : "POST",
        suburl : "/search/certificates",
        bodyFlag : true,
        body : query_data,
    })
}

func (root *RootCert) View(sha256 string) []byte {
    return request(reqOptions{
        method : "GET",
        suburl : "/view/certificates/" + sha256,
        bodyFlag : false,
    })
}

func (root *RootCert)GetAllRoot() []byte {
    query_sql := "tags: root and tags: trusted"
    query_data := Build_body_json(query_sql)
    if query_data == "" {
        fmt.Println("build query statement failed")
        return nil
    }

    fmt.Println("Query: ", query_data)
    return root.Query(query_data)
}

func (root *RootCert)ParseRootQuery(data []byte) {
    var list QueryList
    json.Unmarshal(data, &list)

    if list.Status != "ok" {
        fmt.Println("failed")
        return
    }

    if list.Metadata.Count <= 0 {
        fmt.Println("get result count <= 0")
        return
    }

    var children ChildrenCert
    for _, parsed := range list.Results {
        fmt.Println("Root sha256: ", parsed.Sha256)
        //PushSha256(parsed.Sha256)
        respBody := root.View(parsed.Sha256)
        certdetail := ParseAndStort(respBody)
        time.Sleep(1 * time.Second)
        children.GetAllChildren(certdetail)
    }
}
