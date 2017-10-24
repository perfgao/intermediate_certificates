package main

import (
    "perfgao/censys_io"
    "github.com/golang/glog"
    "flag"
)


func main () {
    flag.Parse()
    defer glog.Flush()

    var root censys.RootCert

    root.GetAllRoot()
    root.Handlersha256()

    root.Clear()
}
