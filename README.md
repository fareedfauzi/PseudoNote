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

<img width="1511" height="819" alt="image" src="https://github.com/user-attachments/assets/45523f17-8010-47c1-bd6e-8f54af576028" />

# Features
1. Convert HexRay's Pseudocode or Assembly into high-level languages such as C. Python, Rust, and others.
3. Automatically rename functions and variables with meaningful names.
4. Provide function explaination, details analysis.
5. Bulk functions renamer.
6. Ask the AI-chat about the current opened function.
7. Automatically generate C function prototypes and type definitions.
8. Analyst Notes - Integrated Markdown editor with live preview with markdown toolbar.
9. Generate high-level, text-based execution tree graph flow.
10. Insert section comments into the pseudocode (Only pseudocode for now).
11. Highlight call and jump instructions in IDA-view and function calls in Pseudocode view.
12. Supports OpenAI, Claude, Gemini, DeepSeek, and local LLMs such as Ollama and LM Studio.
    - Currently, only OpenAI, LM Studio, and OpenAI-compatible providers have been fully tested.
    - Anthropic, Gemini, DeepSeek, and Ollama have not yet been tested.
13. Save all generated data directly into the IDA database (.idb).

# GUI
### Pseudonote Pane
<img width="1535" height="821" alt="image" src="https://github.com/user-attachments/assets/514f7c28-c60b-4e81-a6f0-e03a867ab36e" />

### Demo: Converting IDA-view/Pseudocode to readable C code
![chrome_lEV4Uyor9A](https://github.com/user-attachments/assets/5d7376a6-5156-446f-9725-692b4d7d449c)

### Saved notes 
<img width="729" height="155" alt="image" src="https://github.com/user-attachments/assets/5fa827e1-86cd-409e-8517-7d1e194dd120" />

### Chat with the AI agent about the current function
<img width="1534" height="867" alt="image" src="https://github.com/user-attachments/assets/03a684d2-bef3-49d0-a0d4-35173b409e09" />

### Bulk function renamer pane
<img width="1202" height="882" alt="image" src="https://github.com/user-attachments/assets/9a45e458-899d-436d-a525-e028e5df432e" />

### Call highlighter (IDA view and Pseudocode)
<img width="1690" height="816" alt="image" src="https://github.com/user-attachments/assets/0b39f11b-453d-4bc4-8bff-fbb3e9fafe83" />



