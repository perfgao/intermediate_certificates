package censys

import (
    "github.com/astaxie/beego/orm"
    _ "github.com/go-sql-driver/mysql"
    "time"
    "github.com/golang/glog"

    "perfgao/censys_io/config"
)

const (
    aliasName = "default"
    diverName = "mysql"
)

func Sqlinit(conf config.Sqlconfig) {
    sqlUser := conf.User
    sqlPasswd := conf.Passwd
    sqlHost := conf.Addr
    sqlPort := conf.Port
    sqlDB := conf.DB
    tableName := conf.Table

    db_conn_str := sqlUser + ":" + sqlPasswd + "@tcp(" +sqlHost + ":" +
                    sqlPort + ")/" + sqlDB + "?charset=utf8&parseTime=true"
    //orm.Debug = true
    orm.RegisterDataBase(aliasName, diverName, db_conn_str, 30)
    orm.RegisterModel(new(certificateRecord))
    orm.RunSyncdb(aliasName, false, true)

    dbconn := orm.NewOrm()
    _, err := dbconn.Raw("alter table " + tableName +" convert to character set utf8").Exec()
    if err != nil {
        glog.Fatal("convert character failed, ", err)
    }
}


type certificateRecord struct {
    Id int `pk:"auto"`
    Raw string `orm:"type(text)"`
    Type string `orm:"size(16);index;null"`
    Trusted bool `orm:null`
    Update_time time.Time `orm:"auto_now_add;type(datetime)"`
    Fingerprint_sha256 string `orm:"size(64);unique"`
    Fingerprint_md5 string `orm:"size(32);index"`
    Fingerprint_sha1 string `orm:"size(64);index"`
    Subject_key_id string `orm:"size(128);index"`
    Unexpired bool `orm:null`
    Validity_start string `orm:"size(24)"`
    Validity_end string `orm:"size(24)"`
    Issuer_cm string `orm:"size(512);null"`
    Subject_cm string `orm:"size(512);null"`
    Paths string `orm:"size(2048)"`
    Raw_data string `orm:"type(text)"`
    Support int `orm:"default(0)"`
    Pathlen int `orm:"default(0)"`
}

func insertIntoSql(info certificateRecord) error {
    orm:=orm.NewOrm()
    orm.Using(aliasName)
    _,err:=orm.InsertOrUpdate(&info)
    return err
}
