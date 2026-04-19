# Лабораторна робота №5

**Завдання:** розробити систему «Анти-сніфер» за принципом IDS / IPS, яка в реальному часі сканує вхідний та вихідний трафік на підозрілу активність (скани портів, масові запити тощо) та негайно попереджає користувача, якщо його комп'ютер сканують.

## Принцип роботи програми

Програма працює у трьох режимах.

Перший режим зберігає функціонал попередніх лабораторних робіт і виконує ping для одного хоста або діапазону адрес, після чого записує адреси з відповіддю у файл `responded.txt`, а адреси без відповіді у файл `no_response.txt`.

Другий режим призначений для фільтрації мережевих записів. Користувач може ввести записи вручну або завантажити їх із CSV-файлу у форматі `source_ip,destination_ip,protocol,source_port,destination_port`, а потім відфільтрувати дані за IP-адресами, протоколами, портами та типом трафіку (внутрішній / зовнішній).

Третій режим реалізує IDS / IPS «Анти-сніфер». У реальному часі опитуються активні мережеві з'єднання через `psutil`, формується ковзне вікно подій і аналізується:
- можливий скан портів (коли одне віддалене джерело торкається багатьох локальних портів);
- масові вхідні запити від одного джерела;
- аномально інтенсивна вихідна активність.

Якщо пороги перевищені, програма негайно виводить попередження `ALERT` з рівнем небезпеки.

## Код програми

### `index.py`

```py
from dataclasses import dataclass
from collections import defaultdict, deque
import ipaddress
import time
from typing import Callable

try:
	from pythonping import ping
except ModuleNotFoundError:
	ping = None

try:
	import psutil
except ModuleNotFoundError:
	psutil = None


RESPONDED_FILE = "responded.txt"
NO_RESPONSE_FILE = "no_response.txt"


@dataclass(frozen=True)
class TrafficRecord:
	source_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
	destination_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
	protocol: str
	source_port: int
	destination_port: int


@dataclass(frozen=True)
class NetObservation:
	direction: str
	remote_ip: str
	local_port: int
	remote_port: int


@dataclass(frozen=True)
class SuspiciousEvent:
	level: str
	message: str


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


def parse_int_input(prompt: str, default: int, min_value: int = 1) -> int:
	raw_value = input(prompt).strip()
	if not raw_value:
		return default

	try:
		parsed = int(raw_value)
	except ValueError:
		print(f"Invalid number, using default {default}.")
		return default

	if parsed < min_value:
		print(f"Value must be at least {min_value}, using default {default}.")
		return default

	return parsed


def safe_addr_ip(addr) -> str | None:
	if not addr:
		return None
	if hasattr(addr, "ip"):
		return addr.ip
	if isinstance(addr, tuple) and len(addr) >= 1:
		return addr[0]
	return None


def safe_addr_port(addr) -> int | None:
	if not addr:
		return None
	if hasattr(addr, "port"):
		return int(addr.port)
	if isinstance(addr, tuple) and len(addr) >= 2:
		return int(addr[1])
	return None


def get_connection_snapshot() -> list:
	if psutil is None:
		return []

	try:
		return psutil.net_connections(kind="inet")
	except Exception as exc:
		print(f"Error reading active connections: {exc}")
		return []


def collect_observations() -> list[NetObservation]:
	connections = get_connection_snapshot()
	listening_ports: set[int] = set()

	for connection in connections:
		status = str(getattr(connection, "status", "")).upper()
		local_port = safe_addr_port(getattr(connection, "laddr", None))
		if status == "LISTEN" and local_port is not None:
			listening_ports.add(local_port)

	observations: list[NetObservation] = []
	for connection in connections:
		remote_addr = getattr(connection, "raddr", None)
		if not remote_addr:
			continue

		remote_ip = safe_addr_ip(remote_addr)
		local_port = safe_addr_port(getattr(connection, "laddr", None))
		remote_port = safe_addr_port(remote_addr)

		if remote_ip is None or local_port is None or remote_port is None:
			continue

		direction = "inbound" if local_port in listening_ports else "outbound"
		observations.append(NetObservation(direction, remote_ip, local_port, remote_port))

	return observations


def detect_suspicious_activity(
	observations: deque[tuple[float, NetObservation]],
	scan_port_threshold: int,
	mass_request_threshold: int,
) -> list[SuspiciousEvent]:
	inbound_ports_by_remote: dict[str, set[int]] = defaultdict(set)
	inbound_count_by_remote: dict[str, int] = defaultdict(int)
	outbound_targets_by_remote: dict[str, set[int]] = defaultdict(set)
	outbound_count_by_remote: dict[str, int] = defaultdict(int)

	for _, item in observations:
		if item.direction == "inbound":
			inbound_ports_by_remote[item.remote_ip].add(item.local_port)
			inbound_count_by_remote[item.remote_ip] += 1
		else:
			outbound_targets_by_remote[item.remote_ip].add(item.remote_port)
			outbound_count_by_remote[item.remote_ip] += 1

	events: list[SuspiciousEvent] = []

	for remote_ip, ports in inbound_ports_by_remote.items():
		if len(ports) >= scan_port_threshold:
			events.append(
				SuspiciousEvent(
					"HIGH",
					(
						f"Possible port scan from {remote_ip}: "
						f"{len(ports)} local ports touched in current window"
					),
				)
			)
		elif inbound_count_by_remote[remote_ip] >= mass_request_threshold:
			events.append(
				SuspiciousEvent(
					"MEDIUM",
					(
						f"Mass inbound requests from {remote_ip}: "
						f"{inbound_count_by_remote[remote_ip]} observations in current window"
					),
				)
			)

	for remote_ip, ports in outbound_targets_by_remote.items():
		if len(ports) >= scan_port_threshold:
			events.append(
				SuspiciousEvent(
					"MEDIUM",
					(
						f"Mass outbound probing to {remote_ip}: "
						f"{len(ports)} remote ports touched in current window"
					),
				)
			)
		elif outbound_count_by_remote[remote_ip] >= mass_request_threshold:
			events.append(
				SuspiciousEvent(
					"LOW",
					(
						f"High outbound request rate to {remote_ip}: "
						f"{outbound_count_by_remote[remote_ip]} observations in current window"
					),
				)
			)

	return events


def run_anti_sniffer_mode():
	if psutil is None:
		print("psutil is not installed. Install it to use Anti-sniffer mode: pip install psutil")
		return

	interval_seconds = parse_int_input("Polling interval in seconds [1]: ", default=1)
	window_seconds = parse_int_input("Analysis window in seconds [15]: ", default=15)
	scan_port_threshold = parse_int_input("Port-scan threshold (unique ports) [8]: ", default=8)
	mass_request_threshold = parse_int_input("Mass-request threshold (events in window) [20]: ", default=20)

	print("\nAnti-sniffer IDS/IPS mode started. Press Ctrl+C to stop.")

	recent_observations: deque[tuple[float, NetObservation]] = deque()
	last_seen: dict[tuple[str, str, int, int], float] = {}
	last_alert_at: dict[str, float] = {}
	dedup_seconds = max(2, interval_seconds)
	alert_cooldown_seconds = 8

	try:
		while True:
			now = time.time()
			observations = collect_observations()

			for item in observations:
				key = (item.direction, item.remote_ip, item.local_port, item.remote_port)
				previous_seen = last_seen.get(key)
				if previous_seen is None or now - previous_seen >= dedup_seconds:
					recent_observations.append((now, item))
					last_seen[key] = now

			cutoff = now - window_seconds
			while recent_observations and recent_observations[0][0] < cutoff:
				recent_observations.popleft()

			events = detect_suspicious_activity(
				recent_observations,
				scan_port_threshold=scan_port_threshold,
				mass_request_threshold=mass_request_threshold,
			)

			for event in events:
				event_key = f"{event.level}:{event.message}"
				previous_alert = last_alert_at.get(event_key)
				if previous_alert is not None and now - previous_alert < alert_cooldown_seconds:
					continue

				timestamp = time.strftime("%H:%M:%S")
				print(f"[{timestamp}] ALERT {event.level}: {event.message}\a")
				last_alert_at[event_key] = now

			time.sleep(interval_seconds)
	except KeyboardInterrupt:
		print("\nAnti-sniffer monitoring stopped.")


def main():
	mode = input("Choose mode: 1 - ping, 2 - traffic filter, 3 - anti-sniffer IDS/IPS: ").strip() or "1"

	if mode == "2":
		run_traffic_filter_mode()
	elif mode == "3":
		run_anti_sniffer_mode()
	else:
		run_ping_mode()


if __name__ == "__main__":
	main()
```

## Результат виконання програми

```sh
Choose mode: 1 - ping, 2 - traffic filter, 3 - anti-sniffer IDS/IPS: 3
Polling interval in seconds [1]:
Analysis window in seconds [15]:
Port-scan threshold (unique ports) [8]:
Mass-request threshold (events in window) [20]:

Anti-sniffer IDS/IPS mode started. Press Ctrl+C to stop.
[14:21:03] ALERT HIGH: Possible port scan from 203.0.113.10: 11 local ports touched in current window
[14:21:10] ALERT MEDIUM: Mass inbound requests from 203.0.113.10: 24 observations in current window

^C
Anti-sniffer monitoring stopped.
```

> Для режиму «Анти-сніфер» потрібно встановити пакет `psutil`:
>
> `pip install psutil`
