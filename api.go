package censys

import (
    "github.com/golang/glog"

    "io"
    "io/ioutil"
    "net/http"
    "strings"
    "fmt"
)

var apiUrl string = "https://www.censys.io/api/v1"

const (
    OK_STATUS = 200
    BAD_REQUEST = 400
    NOT_FOUND = 404
    RATE_LIMIT = 429
    INTERNAL_SERVER_ERROR = 500

    FAIL_STATUS = 0
    PROTOCOL_ERROR = 1
    TIMEOUT = 502

)

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

func request(option reqOptions) ([]byte, int) {
    client := &http.Client{}

    var nbody io.Reader
    switch option.bodyFlag {
    case false:
    case true:
        nbody = strings.NewReader(option.body)
    }

    req, err := http.NewRequest(option.method, apiUrl + option.suburl, nbody)
    if err != nil {
        glog.Error(err)
        return nil, FAIL_STATUS
    }

    req.SetBasicAuth(uId, secret)

    resp, err := client.Do(req)
    if err != nil {

        glog.Error(err)

        strerr := fmt.Sprint(err)
        /*
        Post https://www.censys.io/api/v1/search/certificates: net/http: TLS handshake timeout
        Get https://www.censys.io/api/v1/view/certificates/X: dial tcp 172.X.X.X:443: i/o timeout
        */
        if strings.Contains(strerr, "i/o timeout") ||
        strings.Contains(strerr, "TLS handshake timeout") {
            return nil, TIMEOUT
        }

        /*
        Post https://www.censys.io/api/v1/search/certificates: stream error: stream ID 1; PROTOCOL_ERROR
        */
        if strings.Contains(strerr, "stream error: stream ID 1; PROTOCOL_ERROR") {
            return nil, PROTOCOL_ERROR
        }

        return nil, FAIL_STATUS
    }
    defer resp.Body.Close()

    glog.V(2).Infoln(resp.Status)

    respBody, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        glog.Error(err)
        return nil, FAIL_STATUS
    }

    return respBody, resp.StatusCode
}

func query(query_data string) ([]byte, int) {
    return request(reqOptions{
        method : "POST",
        suburl : "/search/certificates",
        bodyFlag : true,
        body : query_data,
    })
}

func view(sha256 string) ([]byte, int) {
    return request(reqOptions{
        method : "GET",
        suburl : "/view/certificates/" + sha256,
        bodyFlag : false,
    })
}

func search(data string) ([]byte, int) {
    return request(reqOptions{
        method : "POST",
        suburl : "/search/certificates",
        bodyFlag : true,
        body : data,
    })
}
