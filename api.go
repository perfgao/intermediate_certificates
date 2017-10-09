package censys

import (
    "fmt"

    "io"
    "io/ioutil"
    "net/http"
    "strings"
)

var apiUrl string = "https://www.censys.io/api/v1"

/* 
* need register by https://www.censys.io/
var uId string = ""
var secret string = ""
*/

type reqOptions struct {
    method string
    suburl string
    body string
    bodyFlag bool
}

func request(option reqOptions) []byte {
    client := &http.Client{}

    var nbody io.Reader
    switch option.bodyFlag {
    case false:
    case true:
        nbody = strings.NewReader(option.body)
    }

    req, err := http.NewRequest(option.method, apiUrl + option.suburl, nbody)
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

    //fmt.Println(string(respBody))

    return respBody
}

func query(query_data string) []byte {
    return request(reqOptions{
        method : "POST",
        suburl : "/search/certificates",
        bodyFlag : true,
        body : query_data,
    })
}

func view(sha256 string) []byte {
    return request(reqOptions{
        method : "GET",
        suburl : "/view/certificates/" + sha256,
        bodyFlag : false,
    })
}

func search(data string) []byte {
    return request(reqOptions{
        method : "POST",
        suburl : "/search/certificates",
        bodyFlag : true,
        body : data,
    })
}
