package censys

import (
   "github.com/astaxie/beego/orm"
   _ "github.com/go-sql-driver/mysql"
   "time"
   "log"
)

const (
    aliasName = "default"
    diverName = "mysql"
    sqlUser = "root"
    sqlPasswd = "root"
    sqlHost = "127.0.0.1"
    sqlPort = "3306"
    sqlDB = "ssl"
)

func init() {
    db_conn_str := sqlUser + ":" + sqlPasswd + "@tcp(" +sqlHost + ":" +
                    sqlPort + ")/" + sqlDB + "?charset=utf8&parseTime=true"
    //orm.Debug = true
    orm.RegisterDataBase(aliasName, diverName, db_conn_str, 30)
    orm.RegisterModel(new(certRecord))
    orm.RunSyncdb(aliasName, false, true)

    dbconn := orm.NewOrm()
    _, err := dbconn.Raw("alter table cert_record convert to character set utf8").Exec()
    if err != nil {
        log.Println("convert character failed, ", err)
    }

    ConnectPool()
    Script()
}


type certRecord struct {
    Id int `pk:"auto"`
    Raw string `orm:"type(text)"`
    Type string `orm:"size(16);index;null"`
    Trusted bool `orm:null`
    Update_time time.Time `orm:"auto_now_add;type(datetime)"`
    Fingerprint_sha256 string `orm:"size(64);unique"`
    Fingerprint_md5 string `orm:"size(32);index"`
    Fingerprint_sha1 string `orm:"size(64);index"`
    Subject_key_id string `orm:"size(64);index"`
    Unexpired bool `orm:null`
    Validity_start string `orm:"size(24)"`
    Validity_end string `orm:"size(24)"`
    Issuer_cm string `orm:"size(512);null"`
    Raw_data string `orm:"type(text)"`
}

func insertIntoSql(info certRecord) error {
    orm:=orm.NewOrm()
    orm.Using("default")
    _,err:=orm.InsertOrUpdate(&info)
    return err
}
