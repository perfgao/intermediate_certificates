package censys

import (
    "github.com/golang/glog"
    "time"
    "encoding/json"
)

type RootCert struct {
}

func (root *RootCert) Query(query_data string) ([]byte, int) {
    return request(reqOptions{
        method : "POST",
        suburl : "/search/certificates",
        bodyFlag : true,
        body : query_data,
    })
}

func (root *RootCert) View(sha256 string) ([]byte, int) {
    return request(reqOptions{
        method : "GET",
        suburl : "/view/certificates/" + sha256,
        bodyFlag : false,
    })
}

func (root *RootCert)GetAllRoot() {
    var page int = 0
    var sleep int = 1
    var query_sql string = "tags: root and tags: trusted"

    for ;; {
        page += 1
        query_data := Build_body_json(query_sql, page)
        if query_data == "" {
            glog.Error("build query statement failed!")
            return
        }

    RETRY2:
        glog.V(2).Infof("query_data: %s", query_data)

        result, status := root.Query(query_data)
        switch status {
        case OK_STATUS:
            glog.V(2).Infoln(string(result))

            if root.ParseRootQuery(result) == 0 {
                return
            }
        case RATE_LIMIT:
            sleep += 5
            time.Sleep(time.Duration(sleep) * time.Second)
            goto RETRY2
        case BAD_REQUEST:
            glog.Error("query_data: %s, BAD_REQUEST", query_data)
        case NOT_FOUND:
            glog.Error("query_data: %s, NOT_FOUND", query_data)
            return
        case INTERNAL_SERVER_ERROR:
            glog.Error("query_data: %s, INTERNAL_SERVER_ERROR", query_data)
        default:
            glog.Error("query_data: %s, status: %d", query_data, status)
        }

        if sleep > 1 {
            sleep -= 1
        }
        time.Sleep(time.Duration(sleep) * time.Second)
    }
}

func (root *RootCert)ParseRootQuery(data []byte) int {
    var list QueryList
    json.Unmarshal(data, &list)

    if list.Status != "ok" {
        glog.Infof("query status not ok: %s", list.Status)
        return -1
    }

    if list.Metadata.Count <= 0 {
        glog.V(2).Infoln("query results is null")
        return 0
    }

    for _, parsed := range list.Results {
        glog.V(2).Infof("result Root sha256: %s", parsed.Sha256)
        PushSha256(parsed.Sha256)
    }

    return len(list.Results)
}

func (root *RootCert) Handlersha256() {
    var sleep int = 1
    for ;; {
        sha256 := GetOneSha256()
        if sha256 == "" {
            break
        }

        time.Sleep(time.Duration(sleep) * time.Second)

    RETRY:
        respBody, status := root.View(sha256)
        switch status {
        case OK_STATUS:
            var children ChildrenCert
            certdetail := ParseAndStort(respBody)
            children.GetAllChildren(certdetail)
        case RATE_LIMIT:
            sleep += 5
            time.Sleep(time.Duration(sleep) * time.Second)
            goto RETRY
        case BAD_REQUEST:
            glog.Error("query sha256: %s, BAD_REQUEST", sha256)
        case NOT_FOUND:
            glog.Infof("query sha256: %s NOT_FOUND", sha256)
            return
        case INTERNAL_SERVER_ERROR:
            glog.Error("query sha256: %s, INTERNAL_SERVER_ERROR", sha256)
        default:
            glog.Error("query sha256: %s, status: %d", sha256, status)
        }

        if sleep > 1{
            sleep -= 1
        }
    }
}
