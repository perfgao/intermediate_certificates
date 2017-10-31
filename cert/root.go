package cert

import (
    "github.com/golang/glog"
    "time"
    "encoding/json"

    "github.com/perfgao/intermediate_certificates/censys"
    "github.com/perfgao/intermediate_certificates/redis"
)

type RootCert struct {
}


func (root *RootCert)GetAllRoot() {
    var page int = 0
    var sleep int = 1
    var query_sql string = "tags: root and tags: trusted"

    for ;; {
        page += 1
        query_data := censys.Build_body_json(query_sql, page)
        if query_data == "" {
            glog.Error("build query statement failed!")
            return
        }

    RETRY2:
        glog.V(2).Infof("query_data: %s", query_data)

        result, status := censys.Query(query_data)
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
            glog.Errorf("query_data: %s, BAD_REQUEST", query_data)
        case NOT_FOUND:
            glog.Errorf("query_data: %s, NOT_FOUND", query_data)
            return
        case INTERNAL_SERVER_ERROR:
            glog.Errorf("query_data: %s, INTERNAL_SERVER_ERROR", query_data)
        case TIMEOUT:
            glog.Errorf("query_data: %s, TIMEOUT", query_data)
            goto RETRY2
        case PROTOCOL_ERROR:
            glog.Errorf("query_data: %s, PROTOCOL_ERROR", query_data)
            goto RETRY2
        default:
            glog.Errorf("query_data: %s, status: %d", query_data, status)
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
        redis.PushSha256(parsed.Sha256)
    }

    return len(list.Results)
}

func (root *RootCert) Handlersha256() {
    var sleep int = 1
    for ;; {
        sha256 := redis.GetOneSha256()
        if sha256 == "" {
            break
        }

        time.Sleep(time.Duration(sleep) * time.Second)

    RETRY:
        respBody, status := censys.View(sha256)
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
            glog.Errorf("query sha256: %s, BAD_REQUEST", sha256)
        case NOT_FOUND:
            glog.Infof("query sha256: %s NOT_FOUND", sha256)
            return
        case INTERNAL_SERVER_ERROR:
            glog.Errorf("query sha256: %s, INTERNAL_SERVER_ERROR", sha256)
        case TIMEOUT:
            glog.Errorf("query_data: %s, TIMEOUT", sha256)
            goto RETRY
        case PROTOCOL_ERROR:
            glog.Errorf("query_data: %s, PROTOCOL_ERROR", sha256)
            goto RETRY
        default:
            glog.Errorf("query sha256: %s, status: %d", sha256, status)
        }

        if sleep > 1{
            sleep -= 1
        }
    }
}
