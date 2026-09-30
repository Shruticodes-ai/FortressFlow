# FortressFlow | AI Passive Threat Gateway for Unidirectional Traffic (SIH26145)

FortressFlow is an autonomous cybersecurity gateway designed to inspect, analyze, and mitigate threats across passive network traffic diodes.

## Quick Start Guide

```bash
# Activate virtual environment
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run server
uvicorn main:app --reload