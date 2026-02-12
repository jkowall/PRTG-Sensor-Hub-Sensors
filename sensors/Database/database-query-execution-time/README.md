# Python Script v2 Sensors for PRTG

This repository hosts ready-to-use Python scripts tailored for PRTG's Script v2 ("Custom Python Script Advanced") sensors. Each script focuses on one specific monitoring scenario that is not covered by PRTG's built-in sensors. All scripts:

- Emit JSON in the format expected by PRTG (`{"prtg": {"result": [...]}}`).
- Fail fast with a structured error payload (`{"prtg": {"error": 1, "text": "..."}}`).
- Use `argparse` so credentials, URLs, or thresholds can be passed as parameters from PRTG's "Parameters" field.
- Avoid non-standard output and write everything (including errors) to stdout only.

## Repository Structure

```
├── README.md
├── requirements.txt
└── sensors
    ├── __init__.py
    ├── prtg_helpers.py
    ├── web_health_check.py
    ├── microservice_latency.py
    ├── license_server_usage.py
    ├── directory_file_check.py
    ├── log_error_count.py
    ├── db_query_time.py
    ├── cloud_cost_check.py
    ├── queue_depth.py
    ├── network_device_custom.py
    └── ssl_cert_expiration.py
```

Each script can be copied to the PRTG probe's `Custom Sensors\python` directory. PRTG will execute the script by calling `python3 <script> <parameters>`. Keep script runtimes short (< 30 seconds) so the probe does not time out.

## Common Helper

`sensors/prtg_helpers.py` provides two convenience functions:

- `print_prtg_results(results: list[dict])` – wraps the supplied channel list, converts to JSON, and prints it.
- `print_prtg_error(message: str)` – prints a compliant error payload and exits with code 1.

Use them in new sensors to keep responses consistent.

## Implemented Use Cases

1. **Web Application Health Check** – Calls `/health` (or any supplied endpoint), parses JSON, and reports component states plus response time.
2. **Microservice API Latency & Status** – Loops through multiple endpoints, tracking per-endpoint latency and HTTP 200 success.
3. **License Server Availability & Usage** – Queries a license server API, exposes remaining seats, usage percentage, and days until expiry.
4. **Directory/File Count & Age** – Counts files in a directory, calculates newest/oldest file age, and flags stale queues/backups.
5. **Custom Log File Error Count** – Parses log files for critical error patterns since the last probe run (using a lightweight state file).
6. **Database Query Execution Time** – Executes a supplied SQL query via the selected driver and reports duration/row count.
7. **Cloud Provider Billing/Cost Check** – Uses AWS Cost Explorer (via `boto3`) to retrieve daily or month-to-date spend.
8. **Third-Party Queue Depth** – Fetches queue depth metrics from HTTP-accessible broker APIs (RabbitMQ, Kafka REST, SQS proxy, etc.).
9. **Custom Network Device Data** – Pulls arbitrary OIDs via SNMPv2c with `pysnmp` and exposes the returned integers/floats.
10. **SSL Certificate Expiration** – Opens an SSL socket to any host:port pair and reports days until certificate expiration.

## Requirements & Installation

Install dependencies on the PRTG probe (or local dev machine):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> Many sensors only need the standard library. Optional dependencies (e.g., `boto3`, `pysnmp`, `psycopg2-binary`, `cx-Oracle`) can be skipped if the corresponding sensor is not deployed.

## Running Locally

```bash
python sensors/web_health_check.py --url https://app.example.com/health --timeout 5
```

The script prints the JSON payload that PRTG expects. Adjust the arguments per script (see the `argparse` descriptions inside each file).

## PRTG Integration Tips

- Use the "Parameters" field to pass arguments, e.g. `--url https://... --timeout 10`.
- Configure the sensor to use Python 3 on the probe (PRTG > Setup > System Administration > Probes).
- For scripts that need credentials or API keys, store them in PRTG device settings and reference `%pass%`, `%windowsdomain%`, etc., or use environment variables set on the probe.
- All scripts exit with code `0` on success and `1` on failure so PRTG can detect failures even before parsing JSON.

## Extending

Fork the helper and follow the same conventions when adding new sensors:

1. Parse CLI arguments with `argparse`.
2. Wrap network/file operations in `try/except` and call `print_prtg_error(...)` on failure.
3. Build a `results` list with `{"channel": "Name", "value": number, "unit": "..."}` dictionaries.
4. Call `print_prtg_results(results)` just before exiting.
