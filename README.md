# SqlScanner - SQL Injection Scanner
> [!IMPORTANT]
> This project is in development; some features may not be fully accessible.

**SqlScanner** is a lightweight tool that detects SQL injection vulnerabilities in web applications by sending commonly used SQL injection payloads to target sites.

## Features
- Scans with a variety of SQL injection payloads to detect vulnerabilities.
- Checks for custom error messages that indicate SQL errors.
- Provides clear, colored output to distinguish between vulnerability and error states.
- Allows for ease of use through command line arguments.

## Disclaimer
Using this tool on websites without proper authorization could be considered **unauthorized access** or **hacking**. It is unethical and potentially illegal to use SqlScanner on websites that you do not own or have explicit permission to test.

## Setup & Usage

### Step 1: Install Python
Ensure you have Python installed on your system. You can download it from the official website: [python.org](python.org/downloads/).

### Step 2: Install Required Libraries
Install the required libraries using pip. Run the following command in your terminal:
```bash
pip install requests argparse

```

### Step 3: Clone the repository:
Clone the SqlScanner repository using Git:
```bash
git clone https://github.com/memirhan/SqlScanner.git
cd SqlScanner
```

### Step 4: Run the Scanner
You can scan a target site for SQL injection vulnerabilities by running the following command in the terminal:
```bash
python main.py -u "<target_url>"
```
Replace `"<target_url>"` with the actual URL, including any query parameters (e.g., `index.php?id=1`).

## Payloads
The scanner uses SQL injection payloads from `payloads.txt` to test various aspects of the target site's SQL query processing, including tautology-based, union-based, error-based, time-based, boolean-based, stacked queries, and out-of-band payloads.

## License
This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## Contributing
All contributions are welcome! Whether it's adding new payloads, optimizing code, or improving documentation, your input is appreciated. Please submit a pull request or open an issue for any suggestions.

## Maintainers
- Muhammet Emirhan: memirhansumer@gmail.com
- Govind S Nair: govindsnair23@gmail.com
- Jayant Agarwal: 01agarwal.jayant@gmail.com
