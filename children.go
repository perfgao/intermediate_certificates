package censys

import (
    "github.com/golang/glog"
    "time"
)

type ChildrenCert struct{

}


func (children *ChildrenCert)GetAllChildren(parent *CertDetails) {
    subjectKeyId := parent.Parsed.Extension.SubjectKeyId
    if subjectKeyId == "" {
        return
    }

    query_sql := "parsed.extensions.authority_key_id: " +
        subjectKeyId + " and tags: trusted and tags: intermediate"

    var page int = 0
    var sleep int = 1
    for ;; {
        page += 1
        bodyData := Build_body_json(query_sql, page)
        if bodyData == "" {
            return
        }

        time.Sleep(5 * time.Second)

    RETRY3:
        result, status := search(bodyData)
        if status == RATE_LIMIT {
            sleep += 5
            time.Sleep(time.Duration(sleep) * time.Second)
            goto RETRY3
        }

        sleep = 1

        if children.ParseChildQuery(result, parent.Parsed.Sha256) == 0 {
            break
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
            PushSha256(parsed.Sha256)
            /*
            respBody := view(parsed.Sha256)
            certdetail := ParseAndStort(respBody)
            time.Sleep(5 * time.Second)
            children.GetAllChildren(certdetail)
            */
        }
    }

    return len(childrens.Results)
}

func ParseAndStort(resp []byte) *CertDetails {
    certdetail := ParseCertDetail(resp)
    cert := AdjustPemFormat(certdetail.Raw)

    var sqlrecord certificateRecord

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

    if err := insertIntoSql(sqlrecord); err != nil {
        glog.Error(err)
    } else {
        glog.V(2).Infoln("insert or update mysql Succ")
    }

    return &certdetail
}
