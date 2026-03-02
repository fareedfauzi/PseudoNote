PseudoNote is a plugin that uses an LLM to assist with malware reversing. It can also be used as a note-taking tool, as it supports Markdown for documenting findings for specific functions during the analysis process. All generated information, including notes and AI outputs, is saved directly in the binary's IDB file.

The deep analyzer featurer are still work in progress btw.

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

# Features
1. Convert HexRay's Pseudocode or Assembly into high-level languages such as C. Python, Rust, and others.
3. Automatically rename functions and variables with meaningful names.
4. Provide function explaination, details analysis.
5. Bulk functions renamer and variable renamer.
6. Bulk function analyzer.
7. Fire and forget Deep Analyzer where it rename functions/variables and summarize everything. User need to choose the entry function to be analyze. WIP
8. Ask the AI-chat about the current opened function.
9. Automatically generate C function prototypes and type definitions.
10. Analyst Notes - Integrated Markdown editor with live preview with markdown toolbar.
11. Generate high-level, text-based execution tree graph flow.
12. Insert section comments into the pseudocode and IDA-view assembly.
    - In the IDA disassembly view, there is also an option to use the currently highlighted/selected range. That selected range will be sent to the LLM (Suitable for shellcode analysis).
13. Highlight call and jump instructions in IDA-view and function calls in Pseudocode view.
14. Supports OpenAI, Claude, Gemini, DeepSeek, and local LLMs such as Ollama and LM Studio.
    - Currently, only OpenAI, LM Studio, and OpenAI-compatible providers have been fully tested.
    - Anthropic, Gemini, DeepSeek, and Ollama have not yet been tested.
15. Save all generated data directly into the IDA database (.idb).

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

### Bulk function analyzer
<img width="1402" height="982" alt="image" src="https://github.com/user-attachments/assets/65c3c249-2b68-4a12-b047-30a18b023cf7" />

### Call highlighter (IDA view and Pseudocode)
<img width="1690" height="816" alt="image" src="https://github.com/user-attachments/assets/0b39f11b-453d-4bc4-8bff-fbb3e9fafe83" />

### Basic shellcode static analysis
- Tested only on msvenom generated shellcode
<img width="1528" height="915" alt="image" src="https://github.com/user-attachments/assets/e4230ec5-5dc9-4070-bbf3-4f283d1fb6ae" />

# Deep Analyzer Approach (WIP)
## PHASE 1: DISCOVERY & PREPARATION
### STAGE 1 - Environment Setup
- Initializes the workspace directories, detects the target binary path from IDA, and validates that all dependencies and AI configurations are ready.

### STAGE 2 - Recursive Call Graph Discovery
- Purpose: Maps the entire "territory" of the binary.
- Details: Starts from your chosen entry point and recursively traverses all calls to build a complete FuncNode graph. This identifies exactly which functions are reachable and how they depend on each other.

### STAGE 3 - Initial Function & Variable Renaming
- Purpose: Eliminates generic IDA names (e.g., sub_401000).
- Details: Uses a "Bottom-Up" approach (starting with leaf functions) to provide initial descriptive names and meaningful variable names (e.g., v1 -> socket_fd). This sets the stage for the deeper analysis.

## PHASE 2: DEEP MALICIOUS CODE ANALYSIS

### STAGE 4 - Initial Code Analysis Assessment + Get Readable C code (SLOW)
- Purpose: The primary "Read" phase.
- Details: Processes functions individually to generate high-quality, readable C code. The AI performs a baseline assessment for every function, identifying technical indicators like encryption, networking, or file I/O.

### STAGE 5 - Contextual Code Analysis Refinement (SLOW)
- Purpose: The "Understanding" phase (Top-Down).
- Details: Re-analyzes functions by providing the AI with "Caller Context". This tells the AI why a function is being called. It is used to upgrade or downgrade risk tags (e.g., a "benign" function that sends a buffer might be upgraded to "malicious" if the context shows it's sending a stolen password).

### STAGE 6 - Initiate Report Generation
- Purpose: The "Reporting" phase.
- Details: Generate Summary, function analysis, ioc extraction, strings analysis, mermaid charts

### STAGE 7 - HTML Report Generation
- Details report analysis in HTML format
