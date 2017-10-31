package main

import (
    "github.com/golang/glog"
    "flag"
    "log"

    "github.com/perfgao/intermediate_certificates/config"
    "github.com/perfgao/intermediate_certificates/mysql"
    "github.com/perfgao/intermediate_certificates/redis"
    "github.com/perfgao/intermediate_certificates/censys"
    "github.com/perfgao/intermediate_certificates/cert"
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
