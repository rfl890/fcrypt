local util = {}

util.run = function(command, args)
    local full_command = command .. " " .. table.concat(args, " ")
    print(full_command)
    local success, _, exit_code = os.execute(full_command)
    return success, exit_code
end

util.safewrite = function(file, string)
    if file:write(string) == nil then 
        print("I/O error")
        os.exit(1)
    end
end

local buffer_size = 128 * 1024
util.cmpfiles = function(f1, f2)
    local file1 = io.open(f1, "rb")
    local file2 = io.open(f2, "rb")
    assert(file1 ~= nil)
    assert(file2 ~= nil)
    local iterator = function()
        return
            file1:read(buffer_size),
            file2:read(buffer_size)
    end
    for file1_contents, file2_contents in iterator do
        if file1_contents ~= file2_contents then 
            return false
        end
    end
    return true
end



return util