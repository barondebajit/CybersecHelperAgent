# CybersecHelperAgent

A cybersecurity related helper agent that takes in user input in natural language and returns the query in natural language too. Uses the function calling functionality of the **Gemini API**.

## Features:

The agent can perform the following functions:
- Perform DNS, reverse DNS and blacklist lookup operations.
- Scan ports of a given IP to check for open ports and also retrieve additional information about the ports.
- Extract file metadata from a few compatible file formats.
- Detect Personally Identifiable Information (PII) in files and texts.

## Requirements:

To use this helper agent, you only need a Gemini API key and an environment with all the dependencies installed.

After getting your own Gemini API key, simply create a .env file with the following secret:

```.env
GEMINI_API_KEY=<your-api-key-here>
```

The dependencies can be installed using:

```pip
pip install -r requirements.txt
```