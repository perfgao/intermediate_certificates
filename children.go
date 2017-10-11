package censys

import (
    "fmt"
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

    bodyData := Build_body_json(query_sql)
    if bodyData == "" {
        return
    }

    result := search(bodyData)
    childrens := ParseIntermediate(result)
    if childrens == nil {
        return
    }

    parentSha256 := parent.Parsed.Sha256
    for _, parsed := range childrens.Results {
        fmt.Println("children_sha256: ", parsed.Sha256)
        if parsed.Sha256 != parentSha256 {
            //PushSha256(parsed.Sha256)
            respBody := view(parsed.Sha256)
            certdetail := ParseAndStort(respBody)
            time.Sleep(5 * time.Second)
            children.GetAllChildren(certdetail)
        }
    }
}

func ParseAndStort(resp []byte) *CertDetails {
    certdetail := ParseCertDetail(resp)
    cert := AdjustPemFormat(certdetail.Raw)

    var sqlrecord certRecord

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
        fmt.Println(err)
    } else {
        fmt.Println("Succ")
    }

    return &certdetail
}
