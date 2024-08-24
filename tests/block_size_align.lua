-- tests for bugs in our usage of fread()

local util = require("util")
local fcrypt_executable = arg[1]

local BUFFER_SIZE_NULL = ("\x00"):rep(1048576)

local file = io.open("1M.bin", "wb")
util.safewrite(file, BUFFER_SIZE_NULL)
file:close()

-- encrypt the file
local success, exit_code = util.run(fcrypt_executable, {"-p", "passw0rd", "-i", "1M.bin", "-o", "1M.bin.enc"})
if not success then os.exit(exit_code) end

-- decrypt it
local success, exit_code = util.run(fcrypt_executable, {"-dp", "passw0rd", "-i", "1M.bin.enc", "-o", "1M.bin.dec"})
if not success then os.exit(exit_code) end

-- decrypt it with the wrong password, if it doesn't fail, something's wrong
local success = util.run(fcrypt_executable, {"-dp", "password", "-i", "1M.bin.enc", "-o", "1M.bin.garbage"})

assert(not success)
assert(util.cmpfiles("1M.bin", "1M.bin.dec"))