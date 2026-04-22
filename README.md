# AI-Powered Cyber Range Simulation
# Security Bot Wars

An AI vs AI cybersecurity competition built by the JMU Madison AI Club Cybersecurity Committee. The red team bot autonomously attacks a vulnerable web application while the blue team bot monitors traffic in real time and blocks attackers instantly.

## What's Inside

- `BOTS/redteam_agent.py` — autonomous attacker that captures flags from DVWA
- `BOTS/blueteam_sgent.py` — real time defender that detects and blocks attacks

## How It Works

The red team bot uses SQL injection, command injection, and brute force attacks to find hidden flags in a DVWA instance running on a cloud server. It enumerates database tables on its own, extracts hidden data, and submits captured flags to a CTFd scoreboard.

The blue team bot streams DVWA access logs in real time via Server-Sent Events, pattern matches every request as it arrives, and blocks attacking IPs through a custom security API that updates UFW firewall rules and nginx blocklists. When an attack is blocked the bot uses a local LLM to explain what happened.

## Setup

Install Python dependencies:

    pip install openai requests sseclient-py

Run LM Studio locally with any model loaded. Then replace the placeholder values at the top of each bot file with your own server IP, API key, and CTFd token.

## Tech Stack

- Python for both bots
- LM Studio for local LLM inference
- DVWA as the vulnerable target
- CTFd for scoring
- Nginx reverse proxy with auth_request for instant blocking
- Flask security API with Server-Sent Events for real-time log streaming
- UFW firewall for IP-level blocking

## Team

Built by the JMU Madison AI Club Cybersecurity Committee for the Spring 2026 AI Club Showcase.
