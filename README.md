PseudoNote is a plugin that uses an LLM to assist with malware reversing. It can also be used as a note-taking tool, as it supports Markdown for documenting findings for specific functions during the analysis process. All generated information, including notes and AI outputs, is saved directly in the binary's IDB file.

# PseudoNote Installation and Setup

### 1. Copy Files
Copy `PseudoNote.py` and the `pseudonote/` folder into your IDA `plugins` directory.

### 2. Install Dependencies
Run this in your terminal:
```bash
pip install openai httpx
```

### 3. Set the API Key for the LLM

**Right-Click** on Pseudocode/IDA-view > **PseudoNote** > **Configure Settings**

<img width="505" height="432" alt="image" src="https://github.com/user-attachments/assets/dda7c949-fd9a-4dd6-b66e-c9f6c4682fc6" />

Test the connection to the API before use the LLM feature.

Once saved, a .ini file will be written to the installation folder. If it fails due to permission issues, the .ini file will be saved in the home directory.

### 4. Use
**Right-Click**: See options in Pseudocode/Disassembly.

<img width="1252" height="767" alt="image" src="https://github.com/user-attachments/assets/b303633e-dacf-4c1a-b8ca-8c6ae06c05f4" />

# Features
1. Convert C or Assembly into high-level languages such as Python, Rust, and others.
2. Automatically rename functions and variables with meaningful
3. Provide function explaination analysis.
4. Bulk functions renamer
5. Automatically generate C function prototypes and type definitions.
6. Analyst Notes - Integrated Markdown editor with live preview with markdown toolbar.
7. Generate high-level, text-based execution tree graph flow.
8. Insert section comments into the pseudocode (Only pseudocode).
9. Highlight call and jump instructions in IDA-view and function calls in Pseudocode view.
10. Supports OpenAI, Claude, Gemini, DeepSeek, and local LLMs such as Ollama and LM Studio. (Currently, only OpenAI and OpenAI-compatible providers have been fully tested.)
11. Save all generated data directly into the IDA database (.idb).

<img width="1535" height="821" alt="image" src="https://github.com/user-attachments/assets/514f7c28-c60b-4e81-a6f0-e03a867ab36e" />

