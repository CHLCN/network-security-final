from PIL import Image
import binascii
import optparse


# 将rgb值转换为十六进制
def rgb2hex(r, g, b):
    return '#{:02x}{:02x}{:02x}'.format(r, g, b)


# 将十六进制编码转换为rgb值
# 将十六进制前的'#'符号去掉
def hex2rgb(hexcode):
    return tuple(map(ord, hexcode[1:].decode('hex')))


# 将字符串转换为二进制编码
# 将编码前的'0b'去掉
def str2bin(message):
    binary = bin(int(binascii.hexlify(message), 16))
    return binary[2:]


# 将二进制字符转换为字符串
def bin2str(binary):
    message = binascii.unhexlify('%x' % (int('0b' + binary, 2)))
    return message


# 如果十六进制蓝色分量上的编码为0-5 则可以将1位信息存入该分量的最后一位
def encode(hexcode, digit):
    if hexcode[-1] in ('0', '1', '2', '3', '4', '5'):
        hexcode = hexcode[:-1] + digit
        return hexcode
    else:
        return None


# 如果十六进制码的最后一位为0或1 则解码
def decode(hexcode):
    if hexcode[-1] in ('0', '1'):
        return hexcode[-1]
    else:
        return None


# 将信息隐藏至图片 以1111111111111110作结束符
def hide(filename, message):
    img = Image.open(filename)
    binary = str2bin(message) + '1111111111111110'
    if img.mode in ('RGBA'):
        img = img.convert('RGBA')
        datas = img.getdata()

        newData = []
        digit = 0
        temp = ''

        for item in datas:
            if (digit < len(binary)):
                newpix = encode(rgb2hex(item[0], item[1], item[2]), binary[digit])
                if newpix == None:
                    newData.append(item)
                else:
                    r, g, b = hex2rgb(newpix)
                    newData.append((r, g, b, 255))
                    digit += 1

            else:
                newData.append(item)

        img.putdata(newData)
        img.save(filename,"PNG")
        return '加密完成！'

def retr(filename):
    img = Image.open
