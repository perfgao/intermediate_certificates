 package censys

 import (
    "fmt"
    "encoding/json"
 )

type QuerySql struct {
    Query string `json:"query"`
    Format string `json:"format, omitempty"`
    Flatten bool `json:flatten, omitempty`
}

func Build_bodySql_json(query string) string {
    var data QuerySql
    data.Query = query
    data.Flatten = false
    data.Format = "json"

    d, err := json.Marshal(data)
    if err != nil {
        fmt.Println(err)
        return ""
    }
    return string(d)
}

func Export() {
    query_sql := "SELECT location.country, count(ip) FROM ipv4.20151020 GROUP BY location.country;"
    query_data := Build_bodySql_json(query_sql)

    fmt.Println("Query: ", query_data)

    reqoption := ReqOptions {
        method : "POST",
        suburl : "/export",
        bodyFlag : true,
        body : query_data,
    }

    fmt.Println(string(Request(reqoption)))
 }
