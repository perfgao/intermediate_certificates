package censys

import (
    "fmt"
)

func data() {
    reqoption := ReqOptions{
        method : "GET",
        suburl : "/data",
        bodyFlag: false,
    }

    fmt.Println(string(Request(reqoption)))
}
