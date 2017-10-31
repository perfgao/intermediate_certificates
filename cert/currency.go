package cert

import (
    "encoding/json"
    "github.com/golang/glog"

    "github.com/perfgao/go-utils/set"
)

/*
"microsoft": {
    "paths": [
        [
        "f055b8ea9057dfa6b95e8a5c138c7644a2bc9b30ecd24dd8d6a9225443748d88", 
        "25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d", 
        "0687260331a72403d909f105e69bcf0d32e1bd2493ffc6d9206d11bcd6770739"
        ]
    ], 
    "blacklisted": false, 
    "had_trusted_path": true, 
    "whitelisted": false, 
    "in_revocation_set": false, 
    "was_valid": true, 
    "valid": true, 
    "parents": [
        "25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d"
    ], 
    "trusted_path": true, 
    "type": "leaf"
}
*/

type PathsInfo struct {
    Paths [][]string
    Blacklisted bool
    Valid bool
    Trusted_path bool
    In_revocation_set bool `json:"in_revocation_set"`
}

type setpathPair struct {
    set *set.Strings
    path *[]string
    count int
}


func SuitPath(cert *CertDetails) (suitpath []string, countMaxNum int) {
    var setpathsArray []*setpathPair
    var psp *setpathPair

    for _, rawmessage := range cert.Validation {
        var pathinfo PathsInfo
        mess, _ := rawmessage.MarshalJSON()
        if err := json.Unmarshal(mess, &pathinfo); err != nil {
            glog.Error(err)
            return
        }

        if (pathinfo.In_revocation_set || !pathinfo.Trusted_path ||
            !pathinfo.Valid || pathinfo.Blacklisted) {
            continue
        }

        infoPaths := pathinfo.Paths
        for index, paths := range infoPaths {
            var localSt set.Strings = set.NewStrings()
            for _, path := range paths {
                localSt.Add(path)
            }

            var isExist = false
            for _, sp := range setpathsArray {
                if sp.set.Equal(localSt) != true {
                    continue
                }

                /* set is equal, means already exist*/
                isExist = true
                /* update count */
                sp.count += 1
                /* update psp */
                if sp.count > countMaxNum {
                    countMaxNum = sp.count
                    psp = sp
                } else if sp.count == countMaxNum {
                    if len(*sp.path) > 0 && len(*sp.path) < len(*psp.path) {
                        psp = sp
                    }
                }

                /*localSt already exist in SETS, need't next list*/
                break
            }

            if isExist == false {
                var localSp setpathPair
                localSp.set = &localSt
                localSp.path = &infoPaths[index]
                localSp.count = 1

                if localSp.count > countMaxNum {
                    countMaxNum = localSp.count
                    psp = &localSp
                } else if localSp.count == countMaxNum {
                    if len(paths) > 0 && len(paths) < len(*psp.path) {
                        psp = &localSp
                    }
                }

                setpathsArray = append(setpathsArray, &localSp)
            }
        }
    }

    if psp == nil || len(*psp.path) == 0 {
        glog.Error("sha256: ", cert.Parsed.Sha256, " not suit path")
        return
    }

    glog.V(2).Infoln("suit path: ", *psp.path, " supportNum: ", countMaxNum)

    suitpath = *psp.path
    return
}
