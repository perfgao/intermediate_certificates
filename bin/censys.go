package main

import (
    "perfgao/censys_io"
    "perfgao/censys_io/config"
    "github.com/golang/glog"
    "flag"
)


func main () {
    file := flag.String("c", "", "config file")
    flag.Parse()
    defer glog.Flush()

    if *file == "" {
        glog.Fatal("must \"-c\" appoint config file")
    }

    var conf config.Config
    conf.Load(*file)

    censys.Sqlinit(conf.Sql)

    var root censys.RootCert

    root.GetAllRoot()
    root.Handlersha256()

    root.Clear()
}
