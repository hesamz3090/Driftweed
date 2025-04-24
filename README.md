```
    ____  _       _  __                _ 
    |  _ \(_) __ _| |/ _| ___  ___ _ __| |
    | | | | |/ _` | | |_ / _ \/ _ \ '__| |
    | |_| | | (_| | |  _|  __/  __/ |  |_|
    |____/|_|\__, |_|_|  \___|\___|_|  (_)
          |___/        v1.0.0

    Author : Hesam Aghajani
    Contact: hesamz3090@gmail.com
    Description: A Network and Website Information Retrieval Tool
```

# Driftweed 🌿

**Driftweed** is a lightweight and powerful information gathering toolkit for networks and websites.  
Easily retrieve HTTP headers, DNS records, WHOIS info, IP & ASN data, open ports, technologies used, and more — all from a simple CLI interface.

![driftweed-banner](https://raw.githubusercontent.com/hesamz3090/driftweed/main/assets/banner.png)

---

## 📦 Features

- 🔍 HTTP Status & Headers  
- 🧠 Technology Detection  
- 🌐 Port Scanning  
- 🧾 WHOIS Lookup  
- 🧠 IP and ASN Info  
- 🧬 DNS Records Check  
- 📸 Page Screenshot
- 🗂 Save Output as JSON  
- ✅ Pretty-printed or raw output  

---

## 📌 Requirements

- Python 3.6+
- See `requirements.txt` for dependencies

---

## ⚙️ Installation

```bash
git clone https://github.com/hesamz3090/driftweed.git
cd driftweed
pip install -r requirements.txt
```

Or install directly using pip (after packaging):

```bash
pip install .
```

---

## 🚀 Usage

```bash
python main.py <target_url> [options]
```

### Examples

```bash
python main.py example.com --http --tech --dns --pretty
python main.py https://example.com --all --output result.json
```

### Options

| Argument        | Description                               |
|-----------------|-------------------------------------------|
| `url`           | Target domain or URL                      |
| `--http`        | Get HTTP status & headers                 |
| `--tech`        | Detect technologies used on the site      |
| `--port`        | Perform basic open port scanning          |
| `--whois`       | Retrieve WHOIS info                       |
| `--ip`          | IP address geolocation lookup             |
| `--asn`         | Autonomous System Number info             |
| `--dns`         | Check DNS records                         |
| `--screenshot`  | Take a screenshot of the target page      |
| `--output FILE` | Save output to a JSON file                |
| `--pretty`      | Print pretty formatted output             |
| `--all`         | Enable all modules                        |

---

## 📁 Example Output

```json
{
  "http_status": 200,
  "headers": {
    "Content-Type": "text/html"
  },
  "ip_info": {
    "ip": "93.184.216.34",
    "country": "United States"
  }
}
```

---


## 📝 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for more details.