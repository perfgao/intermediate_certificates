package cert

import (
    "perfgao/censys_io/censys"
)

const (
    OK_STATUS = censys.OK_STATUS
    BAD_REQUEST = censys.BAD_REQUEST
    NOT_FOUND = censys.NOT_FOUND
    RATE_LIMIT = censys.RATE_LIMIT
    INTERNAL_SERVER_ERROR = censys.INTERNAL_SERVER_ERROR

    FAIL_STATUS = censys.FAIL_STATUS
    PROTOCOL_ERROR = censys.PROTOCOL_ERROR
    TIMEOUT = censys.TIMEOUT

)
