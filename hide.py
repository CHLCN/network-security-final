from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
from PIL import ImageTk
from PIL import Image
import binascii
import rsa
import pem


# 将rgb值转换为十六进制
def rgb2hex(r, g, b):
    return '#{:02x}{:02x}{:02x}'.format(r, g, b)


# 将十六进制编码转换为rgb值
# 将十六进制前的'#'符号去掉
def hex2rgb(hexcode):
    rgb = tuple((int(hexcode[1:3], 16), int(
        hexcode[3:5], 16), int(hexcode[5:], 16)))
    return rgb


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

        for item in datas:
            if (digit < len(binary)):
                newpix = encode(
                    rgb2hex(item[0], item[1], item[2]), binary[digit])
                if newpix == None:
                    newData.append(item)
                else:
                    r, g, b = hex2rgb(newpix)
                    newData.append((r, g, b, 255))
                    digit += 1

            else:
                newData.append(item)

        img.putdata(newData)
        img.save(filename, "PNG")
        return '加密完成！私钥在本目录下的private.pem中'
    return ""

# 将图片中的信息提取出来


def retr(filename):
    img = Image.open(filename)
    binary = ''

    if img.mode in ('RGBA'):
        img = img.convert('RGBA')
        datas = img.getdata()

        for item in datas:
            digit = decode(rgb2hex(item[0], item[1], item[2]))
            if digit == None:
                pass
            else:
                binary = binary + digit
                if (binary[-16:] == '1111111111111110'):
                    print("Success")
                    return bin2str(binary[:-16])

        return bin2str(binary)
    return ""


# 生成公私钥文件
def generate():
    (pubkey, privkey) = rsa.newkeys(1024)

    pub = pubkey.save_pkcs1()
    pubfile = open('public.pem', 'w+')
    pubfile.write(pub.decode())
    pubfile.close()

    pri = privkey.save_pkcs1()
    prifile = open('private.pem', 'w+')
    prifile.write(pri.decode())
    prifile.close()

# 用公钥加密信息


def encr(msg):
    with open('public.pem') as publickfile:
        p = publickfile.read()
        pubkey = rsa.PublicKey.load_pkcs1(p)
    crypto = rsa.encrypt(msg, pubkey)
    return crypto

# 得到私钥文件（privatekey类型）


def getpri():
    with open('private.pem') as privatefile:
        p = privatefile.read()
        privkey = rsa.PrivateKey.load_pkcs1(p)
    return privkey

# 得到私钥文件内容 str类型


def readpri():

    pk = str(pem.parse_file("private.pem")[0]).replace(
        "-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "").replace("\n", "").strip()
    return pk

# 点击按钮选择图片


def myclick():
    global image_name
    frame.filename = filedialog.askopenfilename(
        initialdir=".", title="请选择一个png文件", filetypes=(("png files", "*.png"), ("PNG文件", "*.PNG")))
    image_name = frame.filename
    if frame.filename != "":
        Label(frame, text="您选择的图片："+image_name).grid(row=1)

# 选择加密或解密


def choose(value):
    if value == "加密":
        Label(frame, text="请输入加密信息：").grid(row=5)
    if value == "解密":
        Label(frame, text="请输入解密密钥：").grid(row=5)

    e = Entry(frame, width=20)
    e.grid(row=6)
    Button(frame, text="确定", command=lambda: ensure(
        e.get(), value)).grid(row=7)


def ensure(text, value):
    if image_name == "":
        messagebox.showwarning("警告", "未选择图片")
    elif text == "":
        messagebox.showwarning("警告", "输入不能为空！")

    if value == "加密" and text != "":
        result = hide(image_name, text.encode())
        generate()
        messagebox.showinfo("成功", result)
    if value == "解密":
        result = retr(image_name)
        crypto = encr(result)
        privkey = readpri()
        if text[0:64] == privkey[0:64]:
            msg = rsa.decrypt(crypto, getpri())
            messagebox.showinfo("信息", "隐藏信息："+msg.decode())
        elif text != "":
            messagebox.showwarning("警告", "密钥错误，请输入private.pem中的私钥")


root = Tk()
root.title("png图片加解密")
root.minsize(300, 50)

frame = LabelFrame(root, padx=50, pady=50)
frame.pack(padx=10, pady=10)

image_name = ""

r = StringVar()
r.set("h")


my_btn = Button(frame, text="选择图片", command=myclick,
                fg="blue", bg="white").grid(row=0)
Label(frame, text="未选择图片").grid(row=1)
Label(frame, text="请选择操作：").grid(row=2)

Radiobutton(frame, text="加密", variable=r, value="加密",
            command=lambda: choose(r.get())).grid()
Radiobutton(frame, text="解密", variable=r, value="解密",
            command=lambda: choose(r.get())).grid()


root.mainloop()
