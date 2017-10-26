package censys

import (
    redigo "github.com/garyburd/redigo/redis"
    "os"
    "strconv"
    "github.com/golang/glog"

    "perfgao/censys_io/config"
)

var RedisPool *redigo.Pool
var PushSha_SC *redigo.Script
var handled_key string
var handling_key string

func Redisinit(conf config.Redisconfig) {
    redisHost := conf.Host
    redisPasswd := conf.Passwd
    redisDB := conf.DB
    redisPoolSize := conf.Poolsize

    RedisPool = redigo.NewPool(
        func() (redigo.Conn, error) {
            c, err := redigo.Dial("tcp", redisHost)
            if err != nil {
                return nil, err
            }

            if _, err := c.Do("AUTH", redisPasswd); err != nil {
                c.Close()
                return nil, err
            }

            if _, err := c.Do("SELECT", redisDB); err != nil {
                c.Close()
                return nil, err
            }

            return c, err
        }, redisPoolSize)

    PushSha_SC = redigo.NewScript(3, LUA_PUSH_SHA)

    pid := strconv.Itoa(os.Getpid())
    handled_key = "handled_key_" + pid
    handling_key = "handlings_key_" + pid
}


func PushSha256(sha256 string)  {
    conn := RedisPool.Get()
    defer conn.Close()

    res, err := redigo.Int64(PushSha_SC.Do(conn, handled_key,
                                              handling_key, sha256))
    if err != nil {
        glog.Error(err)
    }

    glog.V(2).Infoln("push sha256 in redis, ", res)
}

func GetOneSha256() string {
    conn := RedisPool.Get()
    defer conn.Close()

    res, err := redigo.String(conn.Do("SPOP", handling_key))
    if err != nil {
        glog.Error(err)
    }

    if res == "" {
        return ""
    }

    glog.V(2).Infoln("get sha256 by redis, ", res)

    conn.Do("SADD", handled_key, res)

    return res
}

func ResetSha256(sha256 string) {
    if sha256 == "" {
        return
    }

    conn := RedisPool.Get()
    defer conn.Close()

    res, err := redigo.String(conn.Do("SADD", handling_key, sha256))
    if err != nil {
        glog.Error(err)
    }

    glog.V(2).Infof("reset %s %s", sha256, res)
}

func redisClear() {
    conn := RedisPool.Get()
    defer conn.Close()

    res, err := redigo.Int64(conn.Do("DEL", handling_key, handled_key))
    if err != nil {
        glog.Error(err)
        return
    }

    glog.V(2).Infoln("Clear: %d", res)
}
