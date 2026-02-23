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

### 4. Usage
**Right-Click**: See options in Pseudocode/Disassembly.

<img width="1441" height="845" alt="image" src="https://github.com/user-attachments/assets/63760745-62dd-446d-ac8a-ae1d445bdc3a" />

# Features
1. Convert C or Assembly into high-level languages such as Python, Rust, and others.
2. Automatically rename functions and variables with meaningful.
3. Provide function explaination analysis.
4. Bulk functions renamer.
5. Ask AI-chat about the current opened function.
6. Automatically generate C function prototypes and type definitions.
7. Analyst Notes - Integrated Markdown editor with live preview with markdown toolbar.
8. Generate high-level, text-based execution tree graph flow.
9. Insert section comments into the pseudocode (Only pseudocode).
10. Highlight call and jump instructions in IDA-view and function calls in Pseudocode view.
11. Supports OpenAI, Claude, Gemini, DeepSeek, and local LLMs such as Ollama and LM Studio.
    - Currently, only OpenAI, LM Studio, and OpenAI-compatible providers have been fully tested.
    - Anthropic, Gemini, DeepSeek, and Ollama have not yet been tested.
12. Save all generated data directly into the IDA database (.idb).

### Pseudonote Pane
<img width="1535" height="821" alt="image" src="https://github.com/user-attachments/assets/514f7c28-c60b-4e81-a6f0-e03a867ab36e" />

### Chat with about the current function
<img width="1534" height="867" alt="image" src="https://github.com/user-attachments/assets/03a684d2-bef3-49d0-a0d4-35173b409e09" />

### Bulk function renamer pane
<img width="1313" height="706" alt="image" src="https://github.com/user-attachments/assets/c9db5dc1-e8c7-4115-90c9-c8fd543d2021" />


