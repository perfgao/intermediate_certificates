package cert

import (
    "github.com/golang/glog"
    "time"
    "strings"

    "perfgao/censys_io/censys"
    "perfgao/censys_io/redis"
    "perfgao/censys_io/mysql"
)

type ChildrenCert struct{

}


func (children *ChildrenCert)GetAllChildren(parent *CertDetails) {
    subjectKeyId := parent.Parsed.Extension.SubjectKeyId
    if subjectKeyId == "" {
        glog.Infof("subjectKeyId is null: %s", parent.Parsed.Sha256)
        return
    }

    query_sql := "parsed.extensions.authority_key_id: " +
        subjectKeyId + " and tags: trusted and tags: intermediate"

    var page int = 0
    var sleep int = 5
    for ;; {
        page += 1
        bodyData := censys.Build_body_json(query_sql, page)
        if bodyData == "" {
            return
        }

        time.Sleep(time.Duration(sleep) * time.Second)

        var bad_req_retry int = 0
    RETRY3:
        result, status := censys.Search(bodyData)
        switch status {
        case OK_STATUS:
            if children.ParseChildQuery(result, parent.Parsed.Sha256) == 0 {
                return
            }
        case RATE_LIMIT:
            sleep += 5
            time.Sleep(time.Duration(sleep) * time.Second)
            goto RETRY3
        case BAD_REQUEST:
            glog.Errorf("query authority_key_id: %s, BAD_REQUEST", subjectKeyId)
            if bad_req_retry < 1 {
                bad_req_retry++
                goto RETRY3
            }
        case NOT_FOUND:
            glog.Infof("query authority_key_id: %s NOT_FOUND", subjectKeyId)
        case INTERNAL_SERVER_ERROR:
            glog.Errorf("query authority_key_id: %s, INTERNAL_SERVER_ERROR",
                        subjectKeyId)
        case TIMEOUT:
            glog.Errorf("query_data: %s, TIMEOUT", subjectKeyId)
            goto RETRY3
        case PROTOCOL_ERROR:
            glog.Errorf("query_data: %s, PROTOCOL_ERROR", subjectKeyId)
            goto RETRY3
        default:
            glog.Errorf("query authority_key_id: %s, status: %d",
                        subjectKeyId, status)
        }

        if sleep > 5 {
            sleep -= 1
        }
    }
}

func (child *ChildrenCert)ParseChildQuery(data []byte, psha256 string) int {
    childrens := ParseIntermediate(data)
    if childrens == nil {
        return 0
    }

    for _, parsed := range childrens.Results {

        glog.V(2).Infoln("get children_sha256: ", parsed.Sha256)

        if parsed.Sha256 != psha256 {
            redis.PushSha256(parsed.Sha256)
        }
    }

    return len(childrens.Results)
}

func ParseAndStort(resp []byte) *CertDetails {
    certdetail := ParseCertDetail(resp)
    cert := AdjustPemFormat(certdetail.Raw)

    var sqlrecord mysql.CertificateRecord

    sqlrecord.Raw_data = string(resp)
    sqlrecord.Raw = string(cert)

    // [unexpired unknown ccadb google-ct root trusted ct]
    for _, tag := range certdetail.Tags {
        switch tag {
        case "root":
            sqlrecord.Type = "root"
        case "trusted":
            sqlrecord.Trusted = true
        case "unexpired":
            sqlrecord.Unexpired = true
        case "intermediate":
            sqlrecord.Type = "intermediate"
        }
    }

    path, supportNum := SuitPath(&certdetail)
    strpath := strings.Join(path, "|")
    glog.V(2).Infoln("to string: ", strpath, " supportNum: ", supportNum)

    sqlrecord.Support = supportNum
    sqlrecord.Paths = strpath
    sqlrecord.Pathlen = len(path)

    parsed := certdetail.Parsed

    sqlrecord.Fingerprint_sha256 = parsed.Sha256
    sqlrecord.Fingerprint_sha1 = parsed.Sha1
    sqlrecord.Fingerprint_md5 = parsed.Md5
    sqlrecord.Subject_key_id = parsed.Extension.SubjectKeyId
    sqlrecord.Validity_start = parsed.Validity.Start
    sqlrecord.Validity_end = parsed.Validity.End
    if len(parsed.Issuer.Cm) > 0 {
        sqlrecord.Issuer_cm = parsed.Issuer.Cm[0]
    }

    if len(parsed.Subject.CN) > 0 {
        sqlrecord.Subject_cm = parsed.Subject.CN[0]
    }

    if err := mysql.Insert(sqlrecord); err != nil {
        glog.Error("sha256: ", parsed.Sha256, ", ",err)
    } else {
        glog.V(2).Infoln("insert or update mysql Succ")
    }

    return &certdetail
}
