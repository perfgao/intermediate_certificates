package config

import (
    "github.com/c4pt0r/ini"
)

type Config struct {
    Sql Sqlconfig
    Redis Redisconfig
    Censys Censysconfig
}

type Sqlconfig struct {
    Addr, Port, User, Passwd, DB, Table string
}

type Redisconfig struct {
    Host, Passwd string
    DB, Poolsize int
}

type Censysconfig struct {
    Uid, Secret string
}

func (c *Config)Load (path string) {
    var conf = ini.NewConf(path)

    var (
        sqladdr = conf.String("mysql", "addr", "127.0.0.1")
        sqlport = conf.String("mysql", "port", "3306")
        sqluser = conf.String("mysql", "user", "test")
        sqlpasswd = conf.String("mysql", "passwd", "test")
        sqldb = conf.String("mysql", "database", "")
        sqltable = conf.String("mysql", "table", "")

        redishost = conf.String("redis", "host", "127.0.0.1:6379")
        redispasswd = conf.String("redis", "passwd", "")
        redisdb = conf.Int("redis", "db", 0)
        redispoolsize = conf.Int("redis", "poolsize", 50)

        censysuid = conf.String("censys", "uid", "")
        censyssec = conf.String("censys", "secret", "")
    )

    conf.Parse()

    c.Sql.Addr = *sqladdr
    c.Sql.Port = *sqlport
    c.Sql.User = *sqluser
    c.Sql.Passwd = *sqlpasswd
    c.Sql.DB = *sqldb
    c.Sql.Table = *sqltable

    c.Redis.Host = *redishost
    c.Redis.Passwd = *redispasswd
    c.Redis.DB = *redisdb
    c.Redis.Poolsize = *redispoolsize

    c.Censys.Uid = *censysuid
    c.Censys.Secret = *censyssec
}
