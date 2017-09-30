package censys

import (
    "fmt"
    "bytes"
    "sort"
    "net/url"
    "encoding/json"
)

type Value map[string][]string

func (v Value) Set(key, value string) {
    v[key] = []string{value}
}

func (v Value) Encode() string {
    if v == nil {
        return ""
    }

    var buf bytes.Buffer
    keys := make([]string, 0, len(v))
    for k := range v {
        keys = append(keys, k)
    }

    sort.Strings(keys)

    for _, k := range keys {
        vs := v[k]
        prefix := url.QueryEscape(k) + "="
        for _, v := range vs {
            if buf.Len() > 0 {
                buf.WriteByte('&')
            }
            buf.WriteString(prefix)
            buf.WriteString(url.QueryEscape(v))
        }
    }

    return buf.String()
}

func build_body_args (body map[string]string) string {
    data := make(Value)

    for k, v := range body {
        data.Set(k, v)
    }

    return data.Encode()
}

/***************************************************/

type Querys struct {
    Query string `json:"query"`
    Page int `json:"page, omitempty"`
    //Fields []string `json:"fields"`
    Flatten bool `json:flatten, omitempty`
}

func Build_body_json(query string) string {
    var data Querys
    data.Query = query
    data.Flatten = true
    data.Page = 1

    d, err := json.Marshal(data)
    if err != nil {
        fmt.Println(err)
        return ""
    }
    return string(d)
}
