package censys

import (
    "encoding/json"

    "fmt"
)


type Querys struct {
    Query string `json:"query"`
    Page int `json:"page, omitempty"`
    //Fields []string `json:"fields"`
    Flatten bool `json:flatten, omitempty`
}

func Build_body_json(query string) string {
    var data Querys
    data.Query = query
    data.Flatten = true
    data.Page = 1

    d, err := json.Marshal(data)
    if err != nil {
        fmt.Println(err)
        return ""
    }
    return string(d)
}


func Search (subjectKeyId string) []byte {
    query_sql := "parsed.extensions.authority_key_id: " +
                 subjectKeyId + " and tags: trusted"
    bodyData := Build_body_json(query_sql)
    if bodyData == "" {
        return nil
    }

    fmt.Println("json: ", bodyData)

    reqoption := ReqOptions{
        method : "POST",
        suburl : "/search/certificates",
        bodyFlag : true,
        body : bodyData,
    }

    respBody := Request(reqoption)

    fmt.Println(string(respBody))

    return respBody
}

