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
    var page int = 1
    query_sql := "tags: root and tags: trusted"
    sleep := 1
    for ;; {
       query_data := Build_body_json(query_sql, page)
        if query_data == "" {
            glog.Error("build query statement failed!")
            return
        }

    RETRY2:
    glog.V(2).Infof("query_data: %s", query_data)

        result, status := root.Query(query_data)
        if status == RATE_LIMIT {
            sleep += 5
            time.Sleep(time.Duration(sleep) * time.Second)
            goto RETRY2
        }

        glog.V(2).Infoln(string(result))

        if res := root.ParseRootQuery(result); res == 0 {
            break
        } else if res == -1 {
            time.Sleep(2 * time.Second)
        }


        sleep = 1
        time.Sleep(1 * time.Second)
        page += 1
    }
}

func (root *RootCert)ParseRootQuery(data []byte) int {
    var list QueryList
    json.Unmarshal(data, &list)

    if list.Status != "ok" {
        glog.Info("status not ok: ", list.Status)
        return -1
    }

    if list.Metadata.Count <= 0 {
        glog.V(2).Infoln("root get result count <= 0")
        return 0
    }

    //var children ChildrenCert
    for _, parsed := range list.Results {
        glog.V(2).Infof("result Root sha256: %s", parsed.Sha256)
        PushSha256(parsed.Sha256)
        /*
        respBody := root.View(parsed.Sha256)
        certdetail := ParseAndStort(respBody)
        time.Sleep(1 * time.Second)
        children.GetAllChildren(certdetail)
        */
    }

    return len(list.Results)
}

func (root *RootCert) Handlersha256() {
    /*get one sha256 by redis*/
    /*api get certificate,and parse get subject-key-id*/
    /*all childrens results by this subject-key-id*/
    /*all childrens sha256 into redis*/
    sleep := 1
    for ;; {
        sha256 := GetOneSha256()
        if sha256 == "" {
            break
        }

        time.Sleep(1 * time.Second)

    RETRY:
        respBody, status := root.View(sha256)
        if status == RATE_LIMIT {
            sleep += 5
            time.Sleep(time.Duration(sleep) * time.Second)
            goto RETRY
        }

        certdetail := ParseAndStort(respBody)

        sleep = 1
        time.Sleep(1 * time.Second)

        var children ChildrenCert
        children.GetAllChildren(certdetail)
    }
}
