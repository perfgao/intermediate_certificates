package censys

const LUA_PUSH_SHA string = `
local handled_set = KEYS[1]
local handling_set = KEYS[2]
local sha256 = KEYS[3]

local exsist = redis.call("SISMEMBER", handled_set, sha256)
if exsist == 1 then
    return
end

redis.call("SADD", handling_set, sha256)
`
