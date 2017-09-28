package censys

import (
    "bytes"
    "sort"
    "net/url"
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
