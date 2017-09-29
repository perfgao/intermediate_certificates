package censys

func View (sha256 string) []byte {
    reqoption := ReqOptions{
        method : "GET",
        suburl : "/view/certificates/" + sha256,
        bodyFlag : false,
    }

    return Request(reqoption)
}
