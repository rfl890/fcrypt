local util = require("util")
local fcrypt_executable = arg[1]

local file = io.open("zero.bin", "wb")
file:close()

-- encrypt the zero-length file
local success, exit_code = util.run(fcrypt_executable, {"-p", "passw0rd", "-i", "zero.bin", "-o", "zero.bin.enc"})
if not success then os.exit(exit_code) end

-- decrypt it
local success, exit_code = util.run(fcrypt_executable, {"-dp", "passw0rd", "-i", "zero.bin.enc", "-o", "zero.bin.dec"})
if not success then os.exit(exit_code) end

assert(util.cmpfiles("zero.bin", "zero.bin.dec"))

-- decrypt it with the wrong password, if it doesn't fail, something's wrong
local success = util.run(fcrypt_executable, {"-dp", "password", "-i", "zero.bin.enc", "-o", "zero.bin.dec"})
assert(not success)