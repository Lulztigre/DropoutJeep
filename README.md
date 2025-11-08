**DropoutJeep** – A Modern Self-Hosted Phishing Simulation & Deliverability Platform

DropoutJeep is an advanced, self-hosted phishing simulation and email deliverability framework built for security teams, researchers, and red-team operators who want full control over every layer of their campaigns — from mail transport to engagement tracking.

Unlike hosted SaaS tools or single-script frameworks, DropoutJeep gives you complete ownership of data, infrastructure, and methodology, while still delivering the polish and automation of a professional-grade platform.
<img width="1117" height="675" alt="image" src="https://github.com/user-attachments/assets/1546ff48-d208-488f-8e6a-7b681db8df74" />
<img width="1114" height="478" alt="image" src="https://github.com/user-attachments/assets/1bb7ddfc-3a11-4ac1-911a-af4103495799" />

## Features

**Full Stack & Self-Contained**
Runs as a Flask web app with built-in models, mailer, dashboards, DKIM/SPF testing, bounce ingestion, and event tracking — no external dependencies or cloud accounts required.

**Research-Oriented Architecture**
Designed to be extensible for email deliverability testing, phishing awareness training, or threat emulation research. Every action is logged, structured, and auditable.

**Real-World Mail Transport Simulation**
Features a connection-pooled SMTP mailer with DKIM signing, envelope tracking, and deliverability validation that mirrors enterprise environments.

**Dynamic Landing Pages & Event Tracking**
Tracks opens, clicks, and form interactions through isolated sandboxed landing pages with per-recipient tokens.

**Modular & Extensible Design**
Built around Blueprints and utility modules (mailer, dialer, renderer, dkim_utils, urlcheck, mail_ingest) — making it easy to extend, automate, or integrate with other systems.

**Privacy-Preserving & Self-Hosted**
No external API calls, no analytics tracking, no data leakage — all events and metrics are stored locally under your control.

<img width="1120" height="449" alt="image" src="https://github.com/user-attachments/assets/005a1d49-ce85-4dac-acc0-074b4b44019c" />

<img width="917" height="1286" alt="image" src="https://github.com/user-attachments/assets/56e923b9-49b1-4b23-9347-f22dff6b9d80" />

**Use Cases**

- Simulated phishing campaigns for awareness or red-team exercises
- Deliverability and authentication testing (SPF, DKIM, DMARC)
- Secure email workflow research and training labs
- Controlled social-engineering experiments in isolated environments
- 
<img width="795" height="784" alt="image" src="https://github.com/user-attachments/assets/a002c8a9-d2ad-4156-89da-4d4d0d2580bf" />


## Tech Stack

- **Backend:** Python / Flask  
- **Frontend:** Jinja2 + TailwindCSS  
- **Database:** SQLite (default) or PostgreSQL  
- **Mailer:** smtplib / DKIM / Custom profiles  
- **Tracking:** tokenized URLs, click/open/credential logging
