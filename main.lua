local ChangeFormat = {
    encrypt = function(input_str)
        local result = ""
        for i = 1, #input_str do
            local char = input_str:sub(i, i)
            if tonumber(char) then
                result = result .. string.char(tonumber(char) + string.byte('a') - 1)
            else
                result = result .. "`k"
            end
        end
        return result
    end,
    
    decrypt = function(input_str)
        local result = ""
        local i = 1
        while i <= #input_str do
            local char = input_str:sub(i, i)
            if char == "`" then
                local next_char = input_str:sub(i + 1, i + 1)
                if next_char == "k" then
                    result = result .. 'E' 
                    i = i + 2 
                else
                    result = result .. "0"
                    i = i + 1
                end
            else
                local digit = string.byte(char) - string.byte('a') + 1
                if digit >= 0 and digit <= 9 then
                    result = result .. tostring(digit)
                else
                    result = result .. 'E'
                end
                i = i + 1
            end
        end
        return result
    end
}

local Hexa = {
    stringToHex = function(str)
        local hex = ""
        
        for i = 1, #str do
            local char = string.byte(str, i)
            hex = hex .. string.format("%02X", char)
        end
        
        return hex
    end,
    hexToString = function(hex)
        local str = ""
        
        for i = 1, #hex, 2 do
            local char = string.char(tonumber(hex:sub(i, i + 1), 16))
            str = str .. char
        end
        
        return str
    end,
}

local Prometheus = {
    new = function(self)
        local o = {
            bxor = function(a, b)
                local result = 0
                local bitValue = 1
            
                while a > 0 or b > 0 do
                    local bitA = a % 2
                    local bitB = b % 2
            
                    if bitA ~= bitB then
                        result = result + bitValue
                    end
            
                    bitValue = bitValue * 2
                    a = math.floor(a / 2)
                    b = math.floor(b / 2)
                end
            
                return result
            end,
        }
        setmetatable(o, self)
        self.__index = self
        return o
    end,
    generateKey = function(self,length)
        local key = ""
        for i = 1, length do
            key = key .. string.format("%02X", math.random(0, 255))
        end
        return key
    end,
    byteToHex = function(self,byte)
        return string.format("%02x", byte)
    end,
    stringToHex = function(self,str)
        return (str:gsub('.', function (c)
            return string.format('%02X', string.byte(c))
        end))
    end,
    hexToString = function(self,hex)
        return hex:gsub('..', function (cc)
            return string.char(tonumber(cc, 16))
        end)
    end,
    enc = function(self,data, key)
        local encrypted_data = ""
        data = tostring(data)
        for i = 1, #data do
            local data_byte = string.byte(data, i)
            local key_byte = string.byte(key, (i - 1) % #key + 1)
            local encrypted_byte = self.bxor(data_byte, key_byte)
            encrypted_data = encrypted_data .. self:byteToHex(encrypted_byte)
        end
        return encrypted_data
    end,
    dec = function(self,encrypted_data_hex, key)
        local decrypted_data = ""
        for i = 1, #encrypted_data_hex, 2 do
            local encrypted_byte = tonumber(encrypted_data_hex:sub(i, i + 1), 16)
            local key_byte = string.byte(key, (i - 1) / 2 % #key + 1)
            local decrypted_byte = self.bxor(encrypted_byte, key_byte)
            decrypted_data = decrypted_data .. string.char(decrypted_byte)
        end
        return decrypted_data
    end
}

local MD5Hasher = {
    new= function(self)
        local o = {
            bxor = function(a, b)
                local result = 0
                local bitValue = 1
            
                while a > 0 or b > 0 do
                    local bitA = a % 2
                    local bitB = b % 2
            
                    if bitA ~= bitB then
                        result = result + bitValue
                    end
            
                    bitValue = bitValue * 2
                    a = math.floor(a / 2)
                    b = math.floor(b / 2)
                end
            
                return result
            end,
            band = function(a, b)
                local result = 0
                local bitValue = 1
            
                while a > 0 and b > 0 do
                    local bitA = a % 2
                    local bitB = b % 2
            
                    if bitA == 1 and bitB == 1 then
                        result = result + bitValue
                    end
            
                    bitValue = bitValue * 2
                    a = math.floor(a / 2)
                    b = math.floor(b / 2)
                end
            
                return result
            end,
            bor = function(a, b)
                local result = 0
                local bitValue = 1
            
                while a > 0 or b > 0 do
                    local bitA = a % 2
                    local bitB = b % 2
            
                    if bitA == 1 or bitB == 1 then
                        result = result + bitValue
                    end
            
                    bitValue = bitValue * 2
                    a = math.floor(a / 2)
                    b = math.floor(b / 2)
                end
            
                return result
            end,
            bnot = function(a)
                local result = 0
                local bitValue = 1
            
                while a > 0 do
                    local bitA = a % 2
            
                    if bitA == 0 then
                        result = result + bitValue
                    end

                    bitValue = bitValue * 2
                    a = math.floor(a / 2)
                end
            
                return result
            end,
            rshift = function(num, shift)
                return math.floor(num / 2^shift)
            end,
            lshift = function(num, shift)
                return num * 2^shift
            end,
            S = {
                7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
                5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
                4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
                6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
            },
            SS = {
                1,  5,  9, 13,  1,  5,  9, 13,  1,  5,  9, 13,  1,  5,  9, 13,
                1,  5,  9, 13,  1,  5,  9, 13,  1,  5,  9, 13,  1,  5,  9, 13,
                1,  5,  9, 13,  1,  5,  9, 13,  1,  5,  9, 13,  1,  5,  9, 13,
                1,  5,  9, 13,  1,  5,  9, 13,  1,  5,  9, 13,  1,  5,  9, 13
            },
            Prometheus = Prometheus:new(),
        }
        setmetatable(o, self)
        self.__index = self
        return o
    end,
    leftrotate = function(self,x, c)
        return self.bor(self.lshift(x, c), self.rshift(x, 32 - c))
    end,
    preprocess = function(self,msg)
        local length = #msg * 8
        msg = msg .. string.char(0x80)
        while #msg % 64 ~= 56 do
            msg = msg .. string.char(0)
        end
        msg = msg .. string.pack("<I8", length)
        return msg
    end,
    enc = function(self, msg, salt)
        if not salt then
            salt = "10"
        end
        local msgWithSalt = msg .. salt
        msgWithSalt = self:preprocess(msgWithSalt)

        local A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

        for i = 1, #msgWithSalt, 64 do
            local chunk = msgWithSalt:sub(i, i + 63)
            local words = {}

            for j = 1, 16 do
                local index = (j - 1) * 4 + 1
                words[j] = string.unpack("<I4", chunk:sub(index, index + 3))
            end

            local a, b, c, d = A, B, C, D

            for j = 1, 64 do
                local f, g

                if j <= 16 then
                    f = self.bor(self.band(b, c), self.band(self.bnot(b), d))
                    g = j - 1
                elseif j <= 32 then
                    f = self.bor(self.band(d, b), self.band(self.bnot(d), c))
                    g = (5 * j + 1) % 16
                elseif j <= 48 then
                    f = self.bxor(b, c, d)
                    g = (3 * j + 5) % 16
                else
                    f = self.bxor(c, self.bor(b, self.bnot(d)))
                    g = (7 * j) % 16
                end

                f = self.band(f + a + (self.lshift(d, 16) + self.rshift(d, 16)) + words[g + 1], 0xFFFFFFFF)
                a, b, c, d = d, b + self:leftrotate(f, (j <= 16) and self.S[j] or self.SS[j % 4 + 1]), b, c
            end

            A = self.band(A + a, 0xFFFFFFFF)
            B = self.band(B + b, 0xFFFFFFFF)
            C = self.band(C + c, 0xFFFFFFFF)
            D = self.band(D + d, 0xFFFFFFFF)
        end

        return string.format("%08x%08x%08x%08x", A, B, C, D)
    end,
    hash = function(self, msg)
        math.randomseed(os.time() + tonumber(tostring(os.time()):reverse():sub(1,6)))
        local key = self.Prometheus:generateKey(16)
        local data_to_encrypt = os.time()

        local encrypted_data_hex = self.Prometheus:enc(data_to_encrypt, key)
        local time = os.time()
        return ChangeFormat.encrypt(Hexa.stringToHex(self:enc(msg, time) .. "." .. encrypted_data_hex .. "." .. key))
    end,
    verify = function(self, msg, hash)
        local hash = ChangeFormat.decrypt(hash)
        hash = Hexa.hexToString(hash)
        if not hash then
            return false
        end
        local hash1 , encrypted_data_hex , key = hash:match("([^.]+).([^.]+).([^.]+)")
        if not hash1 or not encrypted_data_hex or not key then
            return false
        end
        local decrypted_data = self.Prometheus:dec(encrypted_data_hex, key)
        local hash2 = self:enc(msg, decrypted_data)
        return hash1 == hash2
    end,
}
timeStart = os.clock()

local md5hasher = MD5Hasher:new()
local hashedValue = md5hasher:hash("your_message_here")
print(hashedValue)
print(md5hasher:verify("your_message_here", hashedValue))

timeEnd = (os.clock() - timeStart) * 1000 
print("Elapsed time: " .. timeEnd .. " milliseconds")
