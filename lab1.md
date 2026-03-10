# Лабораторна робота №1

**Завдання:** Написати команду `ping` мовою програмування `python`

## Принцип роботи програми

Програма отримує від користувача адресу хоста (IP-адреса чи домен) та кількість пакетів для відправки. Використовуючи бібліотеку [pythonping](https://pypi.org/project/pythonping/), вона виконує ping-запит до вказаного хоста. Результат, включаючи час відповіді та статистику, виводиться на екран.

## Код програми

### `index.py`

```py
from pythonping import ping

def main():
    host = input("Enter the host to ping: ")
    count = int(input("Enter the number of pings to send: "))
    
    print(f"Pinging {host} with {count} packets...")
    response = ping(host, count=count)
    
    print(response)

if __name__ == "__main__":
    main()
```

### `requirements.txt`

```txt
pythonping==1.1.4
```

## Результат виконання програми

```sh
$ python .\index.py
Enter the host to ping: 192.168.1.1
Enter the number of pings to send: 5
Pinging 192.168.1.1 with 5 packets...
Reply from 192.168.1.1, 29 bytes in 3.53ms       
Reply from 192.168.1.1, 29 bytes in 1.35ms       
Reply from 192.168.1.1, 29 bytes in 1.45ms       
Reply from 192.168.1.1, 29 bytes in 1.43ms       
Reply from 192.168.1.1, 29 bytes in 1.33ms       

Round Trip Times min/avg/max is 1.33/1.82/3.53 ms
```