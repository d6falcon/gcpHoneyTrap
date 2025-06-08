# GCP HoneyTrap SSH Server

A high-interaction SSH honeypot that simulates a corporate GCP environment using AI-driven responses. This project is forked from and inspired by [splunk/DECEIVE](https://github.com/splunk/DECEIVE).

## Features

### SSH Server
- Emulates a realistic corporate GCP environment
- Supports interactive and non-interactive SSH sessions
- Implements built-in command emulation for common Linux commands
- Maintains command history (up to 30 commands per user)
- Enforces 2-minute inactivity timeout
- Displays corporate security warning banner on login

### Security Features
- JSON-formatted logging of all activities
- Session tracking with unique identifiers
- Connection details logging (source/destination IPs and ports)
- Authentication attempt monitoring
- Historical log generation for system authenticity

### LLM Integration
- Multiple LLM provider support:
  - OpenAI
  - AWS Bedrock
  - Google Generative AI
  - Ollama
- Session analysis and threat assessment
- Automatic session summaries with BENIGN/SUSPICIOUS/MALICIOUS classification

## Setup

1. Clone the repository:
```bash
git clone https://github.com/d6falcon/gcpHoneyTrap.git
cd gcpHoneyTrap/SSH
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Generate SSH host key:
```bash
ssh-keygen -t rsa -b 4096 -f ssh_host_key
```

4. Configure the server:
- Copy `config.ini.template` to `config.ini`
- Set up your LLM provider credentials
- Configure user accounts and passwords
- Adjust other settings as needed

5. Run the server:
```bash
python3 ssh_server.py
```

## Configuration

The `config.ini` file supports the following sections:

```ini
[honeypot]
log_file = ssh_log.log
sensor_name = your-sensor-name

[ssh]
port = 8022
host_priv_key = ssh_host_key
server_version_string = SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3

[llm]
llm_provider = openai
model_name = gpt-3.5-turbo
trimmer_max_tokens = 64000

[user_accounts]
username1 = password1
username2 = password2
```

## Logging

All activities are logged in JSON format with the following information:
- Timestamp (UTC)
- Session ID
- Source/Destination IPs and ports
- User commands (base64 encoded)
- LLM responses (base64 encoded)
- Session summaries with threat assessment

## Credits

This project is a fork of [splunk/DECEIVE](https://github.com/splunk/DECEIVE) by Splunk Inc. The original DECEIVE (DECeption with Evaluative Integrated Validation Engine) concept and implementation provided the foundation for this GCP-focused honeypot.

## Disclaimer

This software is provided for educational and research purposes only. Usage of this honeypot to monitor systems without authorization is prohibited.
