# Лабораторна робота №2

**Завдання:** Написати команду `ping` мовою програмування `python` для пінгу діапазонів адрес

## Принцип роботи програми

Програма просить користувача ввести IP-адресу або діапазон адрес і кількість пакетів для відправки. Потім вона надсилає ping-запити до кожної адреси і показує, чи відповідає пристрій. На екран виводиться час відповіді та статистику для кожного хоста.

## Код програми

```py
from pythonping import ping
import ipaddress


def ping_single(host: str, count: int):
    print(f"\nPinging {host} with {count} packets...")
    try:
        response = ping(host, count=count)
        print(response)
    except Exception as e:
        print(f"Error pinging {host}: {e}")


def iterate_range(start_ip: str, end_ip: str):
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)
    if start > end:
        start, end = end, start
    current = start
    while current <= end:
        yield str(current)
        current += 1


def main():
    host = input("Enter the host to ping (or range a-b): ")
    count = int(input("Enter the number of pings to send per host: "))

    if "-" in host:
        try:
            start_ip, end_ip = host.split("-", 1)
            ipaddress.IPv4Address(start_ip)
            ipaddress.IPv4Address(end_ip)
        except Exception:
            print("Invalid IP range format. Use start-end with valid IPv4 addresses.")
            return

        for ip in iterate_range(start_ip, end_ip):
            ping_single(ip, count)
    else:
        ping_single(host, count)


if __name__ == "__main__":
    main()
```

## Результат виконання програми

```sh
Enter the host to ping (or range a-b): 192.168.0.1-192.168.0.5
Enter the number of pings to send per host: 2

Pinging 192.168.0.1 with 2 packets...
Reply from 192.168.0.1, 29 bytes in 5.92ms
Reply from 192.168.0.1, 29 bytes in 7.18ms

Round Trip Times min/avg/max is 5.92/6.55/7.18 ms

Pinging 192.168.0.2 with 2 packets...
Request timed out
Request timed out

Round Trip Times min/avg/max is 2000/2000.0/2000 ms

Pinging 192.168.0.3 with 2 packets...
Request timed out
Request timed out


Pinging 192.168.0.4 with 2 packets...
Request timed out
Request timed out

Round Trip Times min/avg/max is 2000/2000.0/2000 ms

Pinging 192.168.0.5 with 2 packets...
Request timed out
Request timed out

Round Trip Times min/avg/max is 2000/2000.0/2000 ms
```

Якщо пристрою за певною адресою немає або він не відповідає, програма чекає 2 секунди і виводить "Request timed out".
