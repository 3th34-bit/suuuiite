# suuuiite
SIEM with ELK Stack and Honeypot Integration

This repository contains a comprehensive tutorial and configuration files to set up a SIEM (Security Information and Event Management) system using an ELK Stack (Elasticsearch, Logstash, Kibana) with a honeypot (Cowrie) for detecting and analyzing cyber threats. The project is aimed at helping SOC analysts and cybersecurity enthusiasts understand attack patterns, improve threat detection, and enhance incident response.
Table of Contents

    Introduction
    Features
    Why This Matters
    System Requirements
    Setup Guide
        Step 1: Install ELK Stack
        Step 2: Deploy Honeypot
        Step 3: Forward Logs
        Step 4: Visualize and Analyze
    How to Use
    Future Improvements
    License

Introduction

This project combines the power of the ELK Stack with a honeypot server to capture, store, and analyze attacker behavior. By simulating vulnerable services, we lure attackers to interact with the system, collect detailed logs, and visualize the data for insights.
Features

    Honeypot (Cowrie): Captures attack patterns, credentials, and commands.
    Log Forwarding: Real-time forwarding of honeypot logs using Filebeat.
    Elasticsearch: Stores and indexes logs for querying.
    Kibana Dashboards: Visualizes attacker data such as geolocation, attack frequency, and commands.
    Threat Insights: Identify malicious IPs, common attack vectors, and trends.

Why This Matters

For SOC analysts, this setup provides:

    Actionable Insights: Understand attacker behavior in a controlled environment.
    Threat Detection: Detect brute force attacks, unauthorized access, and other malicious activities.
    Enhanced Incident Response: Quickly respond to evolving attack trends.

System Requirements

    Operating System: Linux (Ubuntu 20.04 recommended)
    Hardware:
        RAM: 4GB+
        Storage: 20GB+
        CPU: Dual-core processor
    Software:
        Elasticsearch, Logstash, Kibana
        Cowrie Honeypot
        Filebeat for log forwarding

Setup Guide
Step 1: Install ELK Stack

    Install Elasticsearch:

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt-get update && sudo apt-get install elasticsearch

Configure Elasticsearch:

network.host: 127.0.0.1
http.port: 9200

Install Logstash and Kibana:

sudo apt-get install logstash kibana

Start Services:

    sudo systemctl start elasticsearch logstash kibana
    sudo systemctl enable elasticsearch logstash kibana

Step 2: Deploy Honeypot

    Clone and Install Cowrie:

    git clone https://github.com/cowrie/cowrie.git /opt/cowrie

    Configure Cowrie Logging: Update cowrie.cfg to output logs to JSON format.

Step 3: Forward Logs

    Install Filebeat:

sudo apt-get install filebeat

Configure Filebeat: Update filebeat.yml to forward Cowrie logs to Logstash.

filebeat.inputs:
- type: log
  paths:
    - /opt/cowrie/var/log/cowrie/cowrie.json
output.logstash:
  hosts: ["127.0.0.1:5044"]

Start Filebeat:

    sudo systemctl start filebeat
    sudo systemctl enable filebeat

Step 4: Visualize and Analyze

    Access Kibana:
        Navigate to http://<server-ip>:5601.
        Create an index pattern for honeypot-logs.
    Build Dashboards:
        Visualize attack frequency, geolocation, and command usage.

How to Use

    Simulate attacks by interacting with the honeypot (e.g., SSH into it using fake credentials).
    Monitor logs in Kibana for real-time insights.
    Identify malicious IPs and generate alerts for suspicious activities.

Future Improvements

    Integrate with threat intelligence feeds (e.g., AbuseIPDB).
    Expand honeypot coverage (e.g., web, database honeypots).
    Add machine learning models for anomaly detection.

License

This project is licensed under the MIT License. See the LICENSE file for details.
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Cybersecurity Honeypot and SIEM Integration

This project demonstrates a honeypot deployment using Cowrie integrated with an ELK stack for log monitoring and threat detection.

## Features
- High-interaction honeypot (Cowrie) to detect malicious SSH activity.
- Log aggregation and analysis using Elasticsearch, Logstash, and Kibana.
- Real-time alerts for suspicious activity.

## Environment Setup
### AWS EC2 Configuration
- **Honeypot Instance**: t2.medium, Cowrie installed.
- **SIEM Instance**: ELK stack running on Debian.

### Cowrie Setup
- Configured to simulate a vulnerable SSH server.
- Logs sent to ELK stack using Filebeat.

## Visualizations
### Kibana Dashboard
![Kibana Dashboard](screenshots/kibana-dashboard.png)

### Alerts
Sample email alert triggered by failed SSH login attempts:
![Email Alert](screenshots/email-alert.png)

## Lessons Learned
- Importance of centralizing logs for monitoring.
- Understanding common attack patterns and alert configuration.


