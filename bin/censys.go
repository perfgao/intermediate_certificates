package main

import (
    "perfgao/censys_io"
)


func main () {
    var root RootCert

    root.ParseRootQuery(root.GetAllRoot())
}
