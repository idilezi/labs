# Лабораторна робота №3

**Завдання:** до застосунку додати сортування відповідей залежно від пінгу(є відповідь/немає відповіді)

## Принцип роботи програми

.

## Код програми

``` from pythonping import ping
import ipaddress


RESPONDED_FILE = "responded.txt"
NO_RESPONSE_FILE = "no_response.txt"


def has_any_reply(response) -> bool:
    """Return True if at least one ping packet received a reply."""
    for attr in ("stats_packets_returned", "packets_received", "packets_returned"):
        value = getattr(response, attr, None)
        if value is not None:
            return int(value) > 0

    try:
        return any(bool(getattr(packet, "success", False)) for packet in response)
    except Exception:
        pass

    success = getattr(response, "success", None)
    if callable(success):
        try:
            return bool(success())
        except Exception:
            return False
    return bool(success)


def ping_single(host: str, count: int):
    print(f"\nPinging {host} with {count} packets...")
    try:
        response = ping(host, count=count)
        print(response)
        return has_any_reply(response)
    except Exception as e:
        print(f"Error pinging {host}: {e}")
        return False


def iterate_range(start_ip: str, end_ip: str):
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)
    if start > end:
        start, end = end, start
    current = start
    while current <= end:
        yield str(current)
        current += 1


def write_host_result(host: str, has_reply: bool):
    target_file = RESPONDED_FILE if has_reply else NO_RESPONSE_FILE
    with open(target_file, "a", encoding="utf-8") as f:
        f.write(f"{host}\n")


def main():
    host = input("Enter the host to ping (or range a-b): ")
    count = int(input("Enter the number of pings to send per host: "))

    # Start each run with fresh output files.
    open(RESPONDED_FILE, "w", encoding="utf-8").close()
    open(NO_RESPONSE_FILE, "w", encoding="utf-8").close()

    if "-" in host:
        try:
            start_ip, end_ip = host.split("-", 1)
            ipaddress.IPv4Address(start_ip)
            ipaddress.IPv4Address(end_ip)
        except Exception:
            print("Invalid IP range format. Use start-end with valid IPv4 addresses.")
            return

        for ip in iterate_range(start_ip, end_ip):
            has_reply = ping_single(ip, count)
            write_host_result(ip, has_reply)
    else:
        has_reply = ping_single(host, count)
        write_host_result(host, has_reply)

    print(f"\nAddresses with response were written to: {RESPONDED_FILE}")
    print(f"Addresses without response were written to: {NO_RESPONSE_FILE}")


if __name__ == "__main__":
    main() 
```

Результат виконання програми:

Ping one or more targets. Targets can be a single host/IP, comma-separated targets, and/or IPv4 ranges such as
192.168.1.1-192.168.1.255.

positional arguments:
  target                Target expression to ping. If omitted, an interactive prompt is shown.

options:
  -h, --help            show this help message and exit
  --responded-file RESPONDED_FILE
                        Output file path for targets that responded.
  --no-response-file NO_RESPONSE_FILE
                        Output file path for targets that did not respond.
$ sudo python3 python_ping.py "192.168.1.1-192.168.1.10,1.1.1.1,google.com" --responded-file responded.txt --no-response-file no_response.txt
Password:
Pinging 12 targets (count=1 each)...
Reply from 192.168.1.1, 29 bytes in 5.37ms
Reply from 192.168.1.2, 29 bytes in 4.94ms
Reply from 192.168.1.3, 29 bytes in 4.33ms
Request timed out
Request timed out
Request timed out
Request timed out
Request timed out
Request timed out
Request timed out
Reply from 1.1.1.1, 29 bytes in 7.3ms
Reply from 142.250.109.100, 29 bytes in 18.26ms

Response summary:
Responded (5): 192.168.1.1, 192.168.1.2, 192.168.1.3, 1.1.1.1, google.com
No response (7): 192.168.1.4, 192.168.1.5, 192.168.1.6, 192.168.1.7, 192.168.1.8, 192.168.1.9, 192.168.1.10

responded.txt:

192.168.1.1
192.168.1.2
192.168.1.3
1.1.1.1
google.com
no_response.txt:

192.168.1.4
192.168.1.5
192.168.1.6
192.168.1.7
192.168.1.8
192.168.1.9
192.168.1.10
