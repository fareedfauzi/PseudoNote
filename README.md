# PseudoNote Installation and Setup

### 1. Copy Files
Copy `PseudoNote.py` and the `pseudonote/` folder into your IDA `plugins` directory.

### 2. Install Dependencies
Run this in your terminal:
```bash
pip install openai httpx
```

### 3. Set the API Key for the LLM

Open the plugin **Right-Click** > **PseudoNote** > **Configure Settings**

<img width="502" height="432" alt="image" src="https://github.com/user-attachments/assets/5a40018d-6169-446e-9cec-2d06653825df" />

Test the connection to the API before use the LLM feature.

Once saved, a .ini file will be written to the installation folder. If it fails due to permission issues, the .ini file will be saved in the home directory.

### 4. Use
- **Right-Click**: See options in Pseudocode/Disassembly.

<img width="1252" height="767" alt="image" src="https://github.com/user-attachments/assets/b303633e-dacf-4c1a-b8ca-8c6ae06c05f4" />

# Features
1. Convert C or Assembly into high-level languages such as Python, Rust, and others.
2. Automatically rename functions and variables with meaningful
3. Provide function explaination analysis.
4. Bulk functions renamer
5. Automatically generate C function prototypes and type definitions.
6. Analyst Notes - Integrated Markdown editor with live preview with markdown toolbar.
7. Logical Flow - Generate high-level, text-based execution flow maps.
8. AI Commenting - Insert structured section comments into the pseudocode (Only pseudocode).
9. Function call Highlighting - Highlight call and jump instructions/functions directly in IDA views and Pseudocode view.
10. Supports OpenAI, Claude, Gemini, DeepSeek, and local LLMs such as Ollama and LM Studio. (Currently, only OpenAI and OpenAI-compatible providers have been fully tested.)
11. Save all generated data directly into the IDA database (.idb).
