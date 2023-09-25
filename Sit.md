![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/59096590-e5f9-40df-9cbb-d5dd272c2d57)

Đọc description mình nghĩ ngay đến Malware Persistence. Khi gặp phải dạng này ta thường kiểm tra các nơi sau:Autostart Registry Key, Windows Services, Scheduled Tasks, WMI Event Consumers. Sau khi kiểm tra mình tìm được một shortcuts đáng nghi trong `[root]\Users\admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`. Việc tạo persistence trong thư mục này không yêu cầu quyền quản trị, vì lý do đó mà nó thường bị lợi dụng khá nhiều, cả trong những giai đoạn đầu của cuộc tấn công tinh vi. Bất kỳ shortcuts nào đc tạo trong folder này đều sẽ thực thi khi người dùng đăng nhặp.

![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/bc7c576e-0e91-49ae-8147-1435496b9ade)

Mình xem trong Target thì thấy nó chạy lệnh sau `C:\Users\admin\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\datahost.exe "C:\Program Files\Common Files\Microsoft Shared\TextConv\tailieu"`

![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/633c8979-d9cd-4647-b75a-4eb0839cbace)

Vào các thư mục trên để tìm đến file thì được file `datahost.exe` nhưng file `tailieu` thì không thấy thay vào đó là file `tailieu.huhu`

![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/2dd364e6-b4a1-44f4-a886-ef96e53634cf)

![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/951f09cb-c1c6-4a9b-b8be-d4710cffb883)

File `datahost.exe` là file thực thi được viết bằng ngôn ngữ python bên mình sử dụng tool [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) và [python-uncompyle6](https://github.com/rocky/python-uncompyle6) để decompile ra code python.

![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/4b9b004d-71c7-4379-944c-fe954e33d54d)

Đoạn code trên mã hoá `aes-cbc` file được truyền vào và lưu vào file mới thêm phần mở rộng `.huhu`. Với key được lấy random theo seed là thời gian tạo file `tailieu`, iv là computer name (hàm `platform.node()`) + thư mục chứ file `tailieu`. 

Tìm thời gian tạo file `tailieu` thì mình xem trong file `$MFT`. Đây là file chứa thông tin quản lý về tất cả các tệp tin và thư mục trên một ổ đĩa hoặc phân vùng NTFS. Dùng tool [MFTECmd](https://www.sans.org/tools/mftecmd/) để xem file thì tìm được thời gian tạo là `8/24/2023  5:08:53 PM` chuyển sang timestamp là 1692896933 (GMT)

![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/c52bc589-62e6-4733-8a28-2cb4f6ebab34)

Computer name tìm trong registry `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`

![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/69f475ca-4a1b-4f0c-bc44-307976267780)

Thông tin đã có đầy đủ thì viết code để decrypt thôi.

```py
import os, sys, random, platform
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256, MD5

def decryption(file, key, iv):
    with open(file,'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(data)
    plaintext = unpad(plaintext, AES.block_size)
    with open('output','wb') as f:
        f.write(plaintext)


filename = 'tailieu.huhu'
sed_ = 1692896933        #8/24/2023  5:08:53 PM
random.seed(sed_)
key = SHA256.new(str(random.randint(1, 13374953)).encode('utf-8')).digest()
iv = MD5.new(('KTMM' + '-' + "C:\Program Files\Common Files\Microsoft Shared\TextConv").encode('utf8')).digest()
decryption(filename, key, iv)
```

Sau khi chạy xong sẽ ra một file pdf chứa QR. 

Flag: KMACTF{Wh3n_Pl4y1n9_CTF,_pl@Y_w1tH_4ll_Ur_h34r7}
