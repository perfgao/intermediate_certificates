package censys

import (
    "encoding/json"
    "github.com/golang/glog"

    "perfgao/utils/set"
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


func SuitPath(cert *CertDetails) []string {
    var maxNum int = 1
    var setpaths []*setpathPair
    var psp *setpathPair

    for _, rawmessage := range cert.Validation {
        var pathinfo PathsInfo
        mess, _ := rawmessage.MarshalJSON()
        if err := json.Unmarshal(mess, &pathinfo); err != nil {
            glog.Error(err)
            return nil
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
            for _, sp := range setpaths {
                if sp.set.Equal(localSt) != true {
                    continue
                }

                /* set is equal, means already exist*/
                isExist = true
                /* update count */
                sp.count += 1
                /* update psp */
                if sp.count > maxNum {
                    maxNum = sp.count
                    psp = sp
                } else if sp.count == maxNum {
                    if len(*sp.path) < len(*psp.path) {
                        psp = sp
                    }
                }

                break
            }

            if isExist == false {
                var localSp setpathPair
                localSp.set = &localSt
                localSp.path = &infoPaths[index]
                localSp.count = 1
                if maxNum == 1 {
                    if psp == nil {
                        psp = &localSp
                    } else if len(paths) < len(*psp.path) {
                        psp = &localSp
                    }
                }

                setpaths = append(setpaths, &localSp)
            }
        }
    }

    if psp == nil || len(*psp.path) == 0 {
        glog.Error("sha256: ", cert.Parsed.Sha256, " not suit path")
        return nil
    }

    glog.V(2).Infoln("suit path: ", *psp.path)

    return *psp.path
}
