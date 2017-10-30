package main

import (
    "github.com/golang/glog"
    "flag"
    "log"

    "perfgao/censys_io/config"
    "perfgao/censys_io/mysql"
    "perfgao/censys_io/redis"
    "perfgao/censys_io/censys"
    "perfgao/censys_io/cert"
)


func main () {
    file := flag.String("c", "", "config file")
    flag.Parse()
    defer glog.Flush()

    if *file == "" {
        log.Fatal("must \"-c\" appoint config file")
    }

    var conf config.Config
    conf.Load(*file)

    mysql.Sqlinit(conf.Sql)
    redis.Redisinit(conf.Redis)
    censys.APIinit(conf.Censys)

    var root cert.RootCert

    root.GetAllRoot()
    root.Handlersha256()

    redis.Clear()
}
