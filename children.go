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
        fmt.Println(parsed.Sha256)
        if parsed.Sha256 != parentSha256 {
            respBody := view(parsed.Sha256)
            certdetail := ParseCertDetail(respBody)
            name := BuildCertName(certdetail)
            //raw := AdjustPemFormat(certdetail.Raw)
            //fmt.Println(string(raw))
            WritePEMFile(certdetail, "./intermediate/" + name)
            time.Sleep(5 * time.Second)
            children.GetAllChildren(&certdetail)
        }
    }
}
