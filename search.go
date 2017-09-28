package censys

import (
    "net/http"
    "io/ioutil"
    "strings"
    "encoding/json"

    "fmt"
)


type Querys struct {
    Query string `json:"query"`
    Page int `json:"page, omitempty"`
    //Fields []string `json:"fields"`
    Flatten bool `json:flatten, omitempty`
}

func build_body_json(query string) string {
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
    client := &http.Client{}
/*
    bodyData := map[string]string{
        "query": "www.json.cn",
    }
*/
   query_sql := "parsed.extensions.authority_key_id: " + subjectKeyId + " and tags: trusted"
    bodyData := build_body_json(query_sql)
    if bodyData == "" {
        return nil
    }
    fmt.Println("json: ", bodyData)
    body := strings.NewReader(bodyData)

    req, err := http.NewRequest("POST", apiUrl + "/search/certificates", body)
    if err != nil {
        fmt.Println(err)
        return nil
    }

    req.SetBasicAuth(uId, secret)

    resp, err := client.Do(req)
    if err != nil {
        fmt.Println(err)
        return nil
    }
    defer resp.Body.Close()

    fmt.Println(resp.Status)

    respBody, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Println(err)
        return nil
    }

    fmt.Println(string(respBody))

    return respBody
}

