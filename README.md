# 🔐 Splunk Agentic Investigator

![Docker](https://img.shields.io/badge/Docker-Containerized-blue?logo=docker&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk-Enterprise-black?logo=splunk)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-pgvector-blue?logo=postgresql)
![Grafana](https://img.shields.io/badge/Grafana-Dashboard-orange?logo=grafana)
![Ollama](https://img.shields.io/badge/Ollama-LLM_Runtime-darkgreen)
![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![Status](https://img.shields.io/badge/Project-Active-success)

An enterprise-grade, containerized SOC simulation platform integrating
Splunk, vector databases, and LLM-driven analysis to demonstrate
AI-assisted detection engineering and incident investigation workflows.

------------------------------------------------------------------------

## 🏗 Architecture Overview

``` mermaid
flowchart LR
    A[Event Generator<br/>Simulated Windows Security Events] --> B[Splunk HEC<br/>index=soc_sim]
    B --> C[Detection Layer<br/>SPL Searches]
    C --> D[Agent Service<br/>DeepSeek via Ollama]
    D --> E[Embeddings Layer]
    E --> F[PostgreSQL + pgvector]
    F --> G[Grafana<br/>SOC Dashboard]
```

------------------------------------------------------------------------

## 🎯 Project Objectives

-   Detection engineering best practices\
-   Security telemetry normalization\
-   AI-assisted SOC triage workflows\
-   Vector-based incident memory\
-   Enterprise-ready containerized architecture\
-   Load and resiliency testing capability

------------------------------------------------------------------------

## 🚀 Implemented Components

### Infrastructure Layer

-   Dockerized Splunk with HEC enabled (HTTPS)
-   PostgreSQL with pgvector extension
-   Ollama runtime with DeepSeek models
-   Grafana dashboards
-   Multi-service Docker Compose orchestration

### Simulated SOC Telemetry

-   EventCode 4625 -- Failed logon
-   Configurable EPS (events per second)
-   Scenario-based generation (`password_spray`)
-   TLS-secured HEC ingestion

Indexed as:

    index=soc_sim
    sourcetype=winsec
    source=soc-sim

------------------------------------------------------------------------

## 🔎 Detection Example -- Password Spray

``` spl
index=soc_sim sourcetype=winsec event_code=4625
| bin _time span=5m
| stats count as failures dc(user) as distinct_users by _time src_ip
| where failures >= 20 AND distinct_users >= 6
| sort - failures
```

------------------------------------------------------------------------

## 🛠 Deployment

### 1️⃣ Configure Environment

Create a `.env` file:

    SPLUNK_PASSWORD=your_password
    SPLUNK_HEC_TOKEN=your_hec_token

### 2️⃣ Start the Stack

    docker compose up -d

### 3️⃣ Verify Telemetry

    index=soc_sim source="soc-sim"

------------------------------------------------------------------------

## 🧩 Technology Stack

  Layer              Technology
  ------------------ -----------------------
  SIEM               Splunk
  AI Runtime         Ollama (DeepSeek)
  Vector Store       PostgreSQL + pgvector
  Dashboarding       Grafana
  Containerization   Docker
  Backend            Python

------------------------------------------------------------------------

## 🏢 Enterprise Relevance

This platform demonstrates how traditional SOC tooling can be augmented
with:

-   Retrieval-Augmented Generation (RAG)
-   Incident similarity search
-   Memory-aware investigation
-   AI-assisted triage workflows
-   Scalable, containerized security labs
