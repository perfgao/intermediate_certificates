package censys

import (
    "fmt"

    "io"
    "io/ioutil"
    "net/http"
    "strings"
)

type ReqOptions struct {
    method string
    suburl string
    body string
    bodyFlag bool
}

func Request(option ReqOptions) []byte {
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

    fmt.Println(string(respBody))

    return respBody
}
