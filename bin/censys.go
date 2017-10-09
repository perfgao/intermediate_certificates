package main

import (
    "perfgao/censys_io"
)


func main () {
    var root censys.RootCert

    root.ParseRootQuery(root.GetAllRoot())
}
