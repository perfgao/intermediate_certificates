package main

import (
    "perfgao/censys_io"
)


func main () {
    censys.ParseRootQuery(censys.GetAllRoot())
}
