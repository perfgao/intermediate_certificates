package censys

import (
   "encoding/json"
   "fmt"
)

type CentsysInfoExtensions struct {
    SubjectKeyId string `json:"subject_key_id"`
}

type CentsysInfoParsed struct {
    Extensions CentsysInfoExtensions `json:"extensions"`
}

type CentsysInfo struct {
    Parsed CentsysInfoParsed `json:"parsed"`
}

func GetSubjectKeyId (data []byte) string {
    var info CentsysInfo
    json.Unmarshal(data, &info)
    fmt.Println("SubjectKeyId: ", info.Parsed.Extensions.SubjectKeyId)
    return info.Parsed.Extensions.SubjectKeyId
}
