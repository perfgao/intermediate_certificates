package censys

import (
    "net/http"
    "io/ioutil"

    "fmt"
)


func data() {
    client := &http.Client{}
    req, err := http.NewRequest("GET", apiUrl + "/data", nil)
    if err != nil {
        fmt.Println(err)
        return
    }

    req.SetBasicAuth(uId, secret)

    resp, err := client.Do(req)
    if err != nil {
        fmt.Println(err)
        return
    }

    defer resp.Body.Close()

    fmt.Println("Status: ", resp.Status)

    if resp.Status != "200 OK" {
        return
    }

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println(string(body))

}
