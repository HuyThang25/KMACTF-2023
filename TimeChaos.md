![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/885f5fb6-e3b3-4b6d-857d-f19cd1a96beb)

![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/09297c2d-63b3-45c3-8a9d-fb9c5c856bbc)

## Phân tích
Khi làm các bài liên quan đến linux, bước đầu tiên mình thường hay tìm đến file `.bash_history` để xem lịch sử cmd đã được thực thi (trong đường dẫn`\home\debian\.bash_history`).

![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/c66befc0-ae1e-4357-8f27-9c0a0834e5bf)

Đầu tiên thư viện chạy câu lệnh `remina` sau đó là tải `python`, thư viện `scapy` và chạy file `pcapgen.py`. Khi xem bên trong thư mục hiện tại thì thấy có file `pcapgen.py`.
![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/8767ff9a-b862-4726-b91e-5b9897637af7)

.Muốn tìm file thực thi của câu lệnh thì ta vào trong thư mục /bin ( đây là nơi chứa các file thực thi tương ứng với câu lệnh được gọi).

![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/3d2bd2bb-b9f0-47f8-814e-dd6362033f55)

Ở đây mình sử dụng IDA để decompile về code C xem file thực hiện chức năng gì

![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/02c5e598-d677-4e00-bb44-0a146b0e0a3c)

Đọc qua thì chương trình đọc file `/home/debian/fl.png` rồi xor với host name được lấy thông qua hàm `gethostname()` gán vào biến `name`. Sau đó lại tiếp tục xor với một giá trị random từ [0,255] và lưu vào file `/home/debian/fl.kma`.

Tiếp theo là tới file `pcapgen.py`

![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/10700457-c4b9-4168-88dd-8327e1585c84)

Nó lấy dữ liệu từ file `fl.kma` gửi từng byte tương ứng với mỗi gói tin tới  địa chỉ `192.168.53.53` bằng giao thức ICMP và lưu vào file `/tmp/temp.pcap`. Sau đó shuffle các gói tin rồi lại lưu vào file `/tmp/chaos.pcap`. 


Tiếp theo là xoá 2 file `/tmp/temp.pcap` và `fl.kma` ở 2 câu lệnh cuối.

![image](https://github.com/HuyThang25/KMACTF-2023/assets/93728466/66451983-3fb2-420d-bb0a-f084386cb8b4)



## Solution

Xâu chuỗi hết những sự kiện trên lại, mình tìm ra hướng giải quyết sau. Do chương trình chỉ shuffle thứ tự mà không thay đổi thời gian các gói tin nên ta có thể sắp xếp lại các gói tin ở file `chaos.pcap` thì sẽ được file `temp.pcap` ban đầu.
Mình sử dụng tshark để dump data trong các gói tin và sử dụng các tool sau để sắp xếp:

```
tshark -nr /tmp/chaos.pcap -T fields -e frame.time -e data.data | sort -k1,1 | awk '{print $6}' | tr -d '\n' | xxd -p -r > encrypted_data.txt
```

Tiếp theo là tìm hostname để decrypt. Mở file `etc/hostname` ta sẽ thấy host name là `debian`. Do đã biết file cần tìm là png nên ta chỉ việc xor với giá trị 0x89 (byte đầu của file png) để lấy được giá trị random. Sử dụng [Cyberchef](https://cyberchef.org/#recipe=XOR(%7B'option':'UTF8','string':'debian'%7D,'Standard',false)XOR(%7B'option':'Hex','string':'89'%7D,'Standard',false)To_Hex('Space',0/disabled)&input=ZLylp%2BXt9%2Bbr4OjqpKSvsujn7Zjr4OiT5ezr4OiWHKUQ4OjmnqWvobyfNwExIZokzeDvsBcYotfSOmaxVi7jkrC4P5jbbyZPzfwscdQAGlUVHJRFmz0cMouT52bRXJbF6eFn7TyP0vbuojzmZ2sMm9wnYYKo8Ubjej0UpLnXcAjaWveiwk3iwfJz39xIi7hxdWGVXiLhYOJIKtfeB%2BReQZX9gKlYBNGsVV8u/sX3BAInCJzTNhCPDW6QMqowsH6/XEwjnmdlJgTxlAyHbqLriInQN2ZZbcalNS3sDSeP9nbub5qvtKUliI6HmeaxecwzqMyw9GQRTsCryq3i%2B7RcpTQP/7iSaeXr%2BGqFHfG6b4oqIWKQgT4T%2BVA2u7iiVsIctElDi1zwuNooTLAn%2BxI5KWI2xESRqa7KAV7UMIDYR8AhDMjk6IszNoDMR/oTdOvJSAzMr/Shsk0BBeAC7/egOgw8maq0Q8twyjji/848q1tL7ELL6ZwMhpzst8ENUevzThFDEmo1o1G7hVzwQNq/78SGzDKDxxLmek59NwGye37r4OjnpKmlpEaljW4) để decrypt ta sẽ được flag.

