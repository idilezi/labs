# Лабораторна робота №4

**Завдання:** додати до програми можливості фільтрації зовнішнього і внутрішнього трафіку за IP-адресами, протоколами, портами.

## Принцип роботи програми

Програма працює у двох режимах. Перший режим зберігає можливості попередніх лабораторних робіт і виконує ping для одного хоста або діапазону адрес, після чого записує адреси з відповіддю у файл `responded.txt`, а адреси без відповіді у файл `no_response.txt`.

Другий режим призначений для фільтрації мережевих записів. Користувач може ввести записи вручну або завантажити їх із CSV-файлу у форматі `source_ip,destination_ip,protocol,source_port,destination_port`. Далі програма дозволяє відфільтрувати трафік за IP-адресами джерела і призначення, протоколами, портами та за типом трафіку: внутрішній або зовнішній. Для IP підтримуються окремі адреси, діапазони та підмережі, а для портів - окремі значення і діапазони.

## Код програми

### `index.py`

```py
from dataclasses import dataclass
import ipaddress
from typing import Callable

try:
	from pythonping import ping
except ModuleNotFoundError:
	ping = None


RESPONDED_FILE = "responded.txt"
NO_RESPONSE_FILE = "no_response.txt"


@dataclass(frozen=True)
class TrafficRecord:
	source_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
	destination_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
	protocol: str
	source_port: int
	destination_port: int


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
	if ping is None:
		print("pythonping is not installed. Install it to use ping mode.")
		return False

	print(f"\nPinging {host} with {count} packets...")
	try:
		response = ping(host, count=count)
		print(response)
		return has_any_reply(response)
	except Exception as exc:
		print(f"Error pinging {host}: {exc}")
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
	with open(target_file, "a", encoding="utf-8") as file_handle:
		file_handle.write(f"{host}\n")


def split_values(raw_value: str) -> list[str]:
	return [item.strip() for item in raw_value.split(",") if item.strip()]


def is_internal_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
	return address.is_private or address.is_loopback or address.is_link_local


def classify_traffic(record: TrafficRecord) -> str:
	return "internal" if is_internal_ip(record.source_ip) and is_internal_ip(record.destination_ip) else "external"


def parse_ip_selector(selector: str) -> Callable[[ipaddress.IPv4Address | ipaddress.IPv6Address], bool]:
	selector = selector.strip()
	if not selector:
		raise ValueError("IP selector cannot be empty")

	if "-" in selector:
		start_text, end_text = selector.split("-", 1)
		start = ipaddress.ip_address(start_text.strip())
		end = ipaddress.ip_address(end_text.strip())
		if start.version != end.version:
			raise ValueError("IP range must use addresses from the same family")

		if start <= end:
			low, high = start, end
		else:
			low, high = end, start

		def matches(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
			return address.version == low.version and low <= address <= high

		return matches

	if "/" in selector:
		network = ipaddress.ip_network(selector, strict=False)

		def matches(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
			return address in network

		return matches

	expected = ipaddress.ip_address(selector)

	def matches(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
		return address == expected

	return matches


def build_ip_filter(raw_value: str) -> Callable[[ipaddress.IPv4Address | ipaddress.IPv6Address], bool] | None:
	selectors = split_values(raw_value)
	if not selectors:
		return None

	predicates = [parse_ip_selector(selector) for selector in selectors]

	def matches(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
		return any(predicate(address) for predicate in predicates)

	return matches


def parse_port_selector(selector: str) -> Callable[[int], bool]:
	selector = selector.strip()
	if not selector:
		raise ValueError("Port selector cannot be empty")

	if "-" in selector:
		start_text, end_text = selector.split("-", 1)
		start = int(start_text.strip())
		end = int(end_text.strip())
		if start <= end:
			low, high = start, end
		else:
			low, high = end, start

		def matches(port: int) -> bool:
			return low <= port <= high

		return matches

	expected = int(selector)

	def matches(port: int) -> bool:
		return port == expected

	return matches


def build_port_filter(raw_value: str) -> Callable[[int], bool] | None:
	selectors = split_values(raw_value)
	if not selectors:
		return None

	predicates = [parse_port_selector(selector) for selector in selectors]

	def matches(port: int) -> bool:
		return any(predicate(port) for predicate in predicates)

	return matches


def build_protocol_filter(raw_value: str) -> set[str] | None:
	protocols = {item.upper() for item in split_values(raw_value)}
	return protocols or None


def parse_traffic_record(line: str) -> TrafficRecord:
	parts = [part.strip() for part in line.split(",")]
	if len(parts) != 5:
		raise ValueError("Expected 5 fields: source_ip,destination_ip,protocol,source_port,destination_port")

	source_ip = ipaddress.ip_address(parts[0])
	destination_ip = ipaddress.ip_address(parts[1])
	protocol = parts[2].upper()
	source_port = int(parts[3])
	destination_port = int(parts[4])
	return TrafficRecord(source_ip, destination_ip, protocol, source_port, destination_port)


def prompt_traffic_records() -> list[TrafficRecord]:
	print("Enter traffic records as source_ip,destination_ip,protocol,source_port,destination_port")
	print("Press Enter on an empty line to finish.")
	records: list[TrafficRecord] = []

	while True:
		line = input("Record: ").strip()
		if not line:
			break

		try:
			records.append(parse_traffic_record(line))
		except Exception as exc:
			print(f"Invalid record: {exc}")

	return records


def load_traffic_records_from_file(file_path: str) -> list[TrafficRecord]:
	records: list[TrafficRecord] = []
	with open(file_path, "r", encoding="utf-8") as file_handle:
		for line in file_handle:
			line = line.strip()
			if not line or line.startswith("#"):
				continue
			records.append(parse_traffic_record(line))
	return records


def format_traffic_record(record: TrafficRecord) -> str:
	return (
		f"{record.source_ip}:{record.source_port} -> "
		f"{record.destination_ip}:{record.destination_port} "
		f"{record.protocol} [{classify_traffic(record)}]"
	)


def filter_traffic_records(records: list[TrafficRecord]) -> list[TrafficRecord]:
	source_ip_filter = build_ip_filter(input("Filter source IPs (optional, comma-separated): "))
	destination_ip_filter = build_ip_filter(input("Filter destination IPs (optional, comma-separated): "))
	protocol_filter = build_protocol_filter(input("Filter protocols (optional, comma-separated): "))
	port_filter = build_port_filter(input("Filter ports (optional, comma-separated values or ranges): "))
	scope = input("Filter scope [all/internal/external]: ").strip().lower() or "all"

	if scope not in {"all", "internal", "external"}:
		print("Invalid scope. Use all, internal, or external.")
		return []

	filtered_records: list[TrafficRecord] = []
	for record in records:
		if source_ip_filter is not None and not source_ip_filter(record.source_ip):
			continue
		if destination_ip_filter is not None and not destination_ip_filter(record.destination_ip):
			continue
		if protocol_filter is not None and record.protocol.upper() not in protocol_filter:
			continue
		if port_filter is not None and not (
			port_filter(record.source_port) or port_filter(record.destination_port)
		):
			continue

		traffic_scope = classify_traffic(record)
		if scope != "all" and traffic_scope != scope:
			continue

		filtered_records.append(record)

	return filtered_records


def run_ping_mode():
	host = input("Enter the host to ping (or range a-b): ")
	count = int(input("Enter the number of pings to send per host: "))

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

		for ip_address_text in iterate_range(start_ip, end_ip):
			has_reply = ping_single(ip_address_text, count)
			write_host_result(ip_address_text, has_reply)
	else:
		has_reply = ping_single(host, count)
		write_host_result(host, has_reply)

	print(f"\nAddresses with response were written to: {RESPONDED_FILE}")
	print(f"Addresses without response were written to: {NO_RESPONSE_FILE}")


def run_traffic_filter_mode():
	records_source = input("Enter path to traffic CSV file or press Enter to enter records manually: ").strip()
	if records_source:
		try:
			records = load_traffic_records_from_file(records_source)
		except Exception as exc:
			print(f"Error reading traffic file: {exc}")
			return
	else:
		records = prompt_traffic_records()

	if not records:
		print("No traffic records were provided.")
		return

	filtered_records = filter_traffic_records(records)

	print(f"\nMatched {len(filtered_records)} of {len(records)} records:")
	for record in filtered_records:
		print(format_traffic_record(record))


def main():
	mode = input("Choose mode: 1 - ping, 2 - traffic filter: ").strip() or "1"

	if mode == "2":
		run_traffic_filter_mode()
	else:
		run_ping_mode()


if __name__ == "__main__":
	main()
```

## Результат виконання програми

```sh
Choose mode: 1 - ping, 2 - traffic filter: 2
Enter path to traffic CSV file or press Enter to enter records manually:
Enter traffic records as source_ip,destination_ip,protocol,source_port,destination_port
Press Enter on an empty line to finish.
Record: 192.168.1.10,8.8.8.8,TCP,12345,80
Record: 10.0.0.5,192.168.1.20,UDP,53,5353
Record:
Filter source IPs (optional, comma-separated): 192.168.1.10
Filter destination IPs (optional, comma-separated): 8.8.8.8
Filter protocols (optional, comma-separated): TCP
Filter ports (optional, comma-separated values or ranges): 80
Filter scope [all/internal/external]: external

Matched 1 of 2 records:
192.168.1.10:12345 -> 8.8.8.8:80 TCP [external]
```
