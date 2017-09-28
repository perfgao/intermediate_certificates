package censys

import (
    "net/http"
    "io/ioutil"

    "fmt"
)


func View (sha256 string) []byte {
    client := &http.Client{}

    viewUrl := apiUrl + "/view/certificates/" + sha256

    req, err := http.NewRequest("GET", viewUrl, nil)
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

    fmt.Println("Status: ", resp.Status)
    respBody, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Println(err)
        return nil
    }

    return respBody
}
