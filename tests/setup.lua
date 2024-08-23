local io = require("io")

local function safewrite(file, string)
    if file:write(string) == nil then 
        print("I/O error")
        os.exit(1)
    end
end

local BUFFER_SIZE_NULL = ("\x00"):rep(1048576)

print("Creating files...")

-- these are aligned to BUFFER_SIZE and will catch any bugs in fread()/fwrite() 
local one_megabyte = io.open("1M.bin", "wb")
safewrite(one_megabyte, BUFFER_SIZE_NULL)
io.close(one_megabyte)

local two_megabyte = io.open("2M.bin", "wb")
safewrite(two_megabyte, BUFFER_SIZE_NULL)
safewrite(two_megabyte, BUFFER_SIZE_NULL)
io.close(two_megabyte)

-- these are randomly sized
local sz = math.random(1, 100000)
local random_size = io.open("random.bin", "wb")
safewrite(random_size, ("\x00"):rep(sz))
io.close(random_size)

-- > 4GB
-- to test for this, we write and encrypt (0xffffffff - 1) + 16 equal bytes.
-- then, we assert that the first 16 bytes and last 16 bytes are not equal.
local sixtyfourbits = io.open("64.bin", "wb")
for i = 1, 4097 do
    safewrite(sixtyfourbits, BUFFER_SIZE_NULL)
end