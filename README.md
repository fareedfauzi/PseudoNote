
# PseudoNote

**An AI-powered IDA Pro plugin for malware reverse engineering.**

## Table of Contents

- [PseudoNote](#pseudonote)
  - [Table of Contents](#table-of-contents)
  - [What is PseudoNote?](#what-is-pseudonote)
  - [Feature Overview](#feature-overview)
  - [Installation](#installation)
    - [1. Copy the Plugin Files](#1-copy-the-plugin-files)
    - [2. Install Python Dependencies](#2-install-python-dependencies)
    - [3. Configure your AI Provider](#3-configure-your-ai-provider)
  - [Configuration \& AI Providers](#configuration--ai-providers)
  - [Quick Start](#quick-start)
  - [All Actions \& Hotkeys](#all-actions--hotkeys)
  - [Features In Depth](#features-in-depth)
    - [PseudoNote Pane](#pseudonote-pane)
    - [Rename Function](#rename-function)
    - [Rename Variables](#rename-variables)
    - [Add Comments (Pseudocode)](#add-comments-pseudocode)
    - [Add Section Comments (IDA-View)](#add-section-comments-ida-view)
    - [Function Prototype](#function-prototype)
    - [Struct Editor](#struct-editor)
    - [Ask Chat (AI)](#ask-chat-ai)
    - [Bulk Function Renamer](#bulk-function-renamer)
    - [Bulk Variable Renamer](#bulk-variable-renamer)
    - [Bulk Function Analyzer](#bulk-function-analyzer)
    - [Deep Analyzer](#deep-analyzer)
    - [FLOSS Strings Discovery](#floss-strings-discovery)
    - [Shellcode Analysis (Static)](#shellcode-analysis-static)
    - [Call Highlighter](#call-highlighter)
    - [Search Utilities](#search-utilities)
  - [Bulk Analyzer vs Deep Analyzer](#bulk-analyzer-vs-deep-analyzer)
  - [Deep Analyzer Pipeline](#deep-analyzer-pipeline)
    - [PHASE 1: Discovery \& Preparation](#phase-1-discovery--preparation)
      - [Stage 1 — Environment Setup](#stage-1--environment-setup)
      - [Stage 2 — Recursive Call Graph Discovery](#stage-2--recursive-call-graph-discovery)
      - [Stage 3 — Initial Function \& Variable Renaming](#stage-3--initial-function--variable-renaming)
    - [PHASE 2: Deep Malicious Code Analysis](#phase-2-deep-malicious-code-analysis)
      - [Stage 4 — Initial Code Analysis + Readable C Generation](#stage-4--initial-code-analysis--readable-c-generation)
      - [Stage 5 — Contextual Code Analysis Refinement](#stage-5--contextual-code-analysis-refinement)
      - [Stage 6 — Report Data Generation](#stage-6--report-data-generation)
      - [Stage 7 — HTML Report Generation](#stage-7--html-report-generation)
  - [Bulk Analyzer Pipeline](#bulk-analyzer-pipeline)
  - [Data Persistence](#data-persistence)
  - [Configuration File Reference](#configuration-file-reference)
  - [Tips \& Best Practices](#tips--best-practices)
  - [Troubleshooting](#troubleshooting)

---

## What is PseudoNote?

PseudoNote is an IDA Pro plugin that brings AI assistance directly into your reverse engineering workflow. It is designed for malware analysts who want to move faster during malware analysis which automatically renaming unknown `sub_` functions, explaining what code does, generating readable C rewrites, spotting malicious indicators, producing full HTML forensic reports and more!

Everything PseudoNote generates like notes, renamed symbols, AI analysis, chat history - is saved directly into the IDB file, so your work is never lost between sessions.

---

## Feature Overview

| Feature | Description |
|---|---|
| **PseudoNote Pane** | |
| Readable C | Generate AI-rewritten, human-readable C code for the current function; saved to IDB |
| Function Details | View callers, callees, API references, and string references for the current function |
| Analyst Notes | Integrated Markdown editor with live preview and formatting toolbar; saved to IDB |
| Execution Flow | AI-generated plain-English execution flow graph showing branches and intent |
| **Renaming** | |
| Rename Function | AI-powered rename of the current function (Code or Malware mode) |
| Rename Variables | AI suggests meaningful local variable names and applies them |
| Bulk Function Renamer | Batch-rename hundreds of functions with AI using queued workers |
| Bulk Variable Renamer | Batch-rename local variables across many functions |
| **Commenting** | |
| Add Comments | Inline comments added to pseudocode, synced to IDA-view |
| Section Comments | Block-level comments on disassembly sections |
| **Analysis** | |
| Ask Chat (AI) | Persistent dockable chat about the currently open function |
| Bulk Function Analyzer | Tag and classify functions by malware behavior categories |
| Deep Analyzer | Full recursive bottom-up analysis pipeline with HTML forensic report |
| FLOSS Strings Discovery | Discover stack strings, tight strings, and decoded strings |
| Shellcode Analysis | Static analysis of selected shellcode bytes/disassembly |
| Function Prototype | AI infers and applies C calling conventions and prototypes |
| Struct Editor | AI infers struct layout from variable field access patterns |
| **Utilities** | |
| Call Highlighter | Highlight function calls in pseudocode and disassembly views |
| Search Utilities | Search bytes/strings in VirusTotal, Google, GitHub, MSDN, CyberChef |

---

## Installation

### 1. Copy the Plugin Files

Copy these two items into your IDA `plugins/` directory:

- `PseudoNote.py` file
- `pseudonote/` folder

```
<IDA install dir>/
└── plugins/
    ├── PseudoNote.py
    └── pseudonote/
        ├── plugin.py
        ├── handlers.py
        ├── ai_client.py
        ├── config.py
        ├── view.py
        ├── renamer.py
        ├── var_renamer.py
        ├── analyzer.py
        ├── deep_analyzer.py
        ├── report_generator.py
        ├── floss_strings.py
        ├── chat.py
        ├── idb_storage.py
        ├── highlight.py
        ├── api_taxonomy.py
        ├── malware_api_tags.json
        ├── qt_compat.py
        └── ...
```

### 2. Install Python Dependencies

Run the following in your terminal using the same Python that IDA uses:

```bash
pip install openai httpx
```

Optional, to use Anthropic (Claude) or Google Gemini providers:

```bash
pip install anthropic google-generativeai
```

### 3. Configure your AI Provider

Open the settings dialog:

**Right-Click** anywhere in Pseudocode or IDA-View > **PseudoNote** > **Configure Settings...**

Or via the menu: `Edit > Plugins > PseudoNote > Configure Settings...`

Enter your API key, select your provider and model, then click **Test Connection** before saving.

<img width="702" height="532" alt="image" src="https://github.com/user-attachments/assets/2972ac1b-f6f0-485b-9875-0eee9d45a83d" />


> If IDA is installed in `Program Files` and cannot write there, the config will be automatically saved to `~/.pseudonote.ini`. You will be notified when this happens.

---

## Configuration & AI Providers

PseudoNote supports six AI providers:

| Provider | Status | Notes |
|---|---|---|
| OpenAI | Fully tested | GPT-4, GPT-4o, etc. Recommended for best results |
| LM Studio | Fully tested | Local models via OpenAI-compatible endpoint |
| OpenAI-Compatible | Fully tested | Any endpoint speaking the OpenAI API spec |
| DeepSeek | Not fully tested | Compatible with OpenAI endpoint format |
| Anthropic (Claude) | Not fully tested | Requires `anthropic` Python package |
| Google Gemini | Not fully tested | Requires `google-generativeai` Python package |
| Ollama | Not fully tested | Local models via `http://localhost:11434/v1` |

<img width="702" height="532" alt="image" src="https://github.com/user-attachments/assets/b3e40fb1-c9eb-4fc7-91d4-dc4e7c0baa2c" />

> If your provider speaks the OpenAI API spec, use the **OpenAI-Compatible** tab and enter your custom base URL and model name. This works for most self-hosted or alternative providers.

---

## Quick Start

1. Open a binary in IDA Pro and let IDA finish auto-analysis.
2. Navigate to a function in the pseudocode view.
3. Right-click > **PseudoNote** > pick an action.
4. Or use a hotkey from the table below.

<img width="1531" height="957" alt="image" src="https://github.com/user-attachments/assets/88012abf-49e2-4856-8cae-8ab12341b1a7" />

---

## All Actions & Hotkeys

| Action | Hotkey | Availability |
|---|---|---|
| Show PseudoNote Panes | `Ctrl+Alt+G` | Both |
| View Saved Notes | `Ctrl+Alt+L` | Both |
| Configure Settings | menu only | Both |
| Rename Function (Code) | `Ctrl+Alt+N` | Both |
| Rename Function (Malware) | `Ctrl+Alt+M` | Both |
| Rename Variables | `Ctrl+Alt+R` | Both |
| Function Prototype | `Ctrl+Alt+S` | Pseudocode |
| Add Comments (Pseudocode) | `Ctrl+Alt+C` | Pseudocode |
| Add Section Comments (IDA-View) | menu only | Disassembly |
| Delete Comments (Pseudocode) | `Ctrl+Alt+D` | Pseudocode |
| Delete Comments (IDA-View) | menu only | Disassembly |
| Ask Chat (AI) | `Ctrl+Alt+A` | Both |
| Bulk Function Renamer | `Ctrl+Shift+R` | Both |
| Bulk Variable Renamer | `Ctrl+Shift+V` | Both |
| Bulk Function Analyzer | `Ctrl+Shift+A` | Both |
| Deep Analyzer | `Ctrl+Shift+S` | Both |
| FLOSS Strings Discovery | `Ctrl+Shift+F` | Both |
| Shellcode Analysis (Static) | menu only | Disassembly |
| Toggle Call Highlight (Pseudocode) | menu only | Pseudocode |
| Toggle Call Highlight (Graph/Linear) | menu only | Disassembly |
| Struct Editor | right-click on variable | Pseudocode |
| Search Bytes in VirusTotal | right-click, select bytes | Disassembly |
| Add Bytes to CyberChef | right-click, select bytes | Disassembly |
| Search String in VirusTotal | right-click, highlight text | Both |
| Search String in Google | right-click, highlight text | Both |
| Search String in GitHub | right-click, highlight text | Both |
| Search String (WinAPI) in MSDN | right-click, highlight text | Both |
| Add String to CyberChef | right-click, highlight text | Both |

---

## Features In Depth

### PseudoNote Pane

The main dockable side panel. Open it with `Ctrl+Alt+G`.

The pane contains seven tabs, each serving a distinct purpose during analysis.

<img width="1920" height="1057" alt="image" src="https://github.com/user-attachments/assets/d8d919c7-6c7d-4156-99af-a2b2d4eb92c9" />

---

#### Readable Code

Displays AI-generated, human-readable C code for the currently active function. When you click **Generate**, the plugin decompiles the function using Hex-Rays, sends the output to the AI, and receives a cleaned-up, well-commented version of the code.

Key behaviours:

- You can request a rewrite in a different language (Python, Rust, Go, etc.) by selecting the target language before generating.
- The generated code is shown in a syntax-highlighted editor.
- The result is saved to the IDB automatically keyed to the function address, so it is restored the next time you open the same function.
- You can regenerate at any time to get an updated result after renaming or modifying the function.

![Readable code](https://github.com/user-attachments/assets/407f4d58-ae3b-45dc-8c74-85c12543ac7e)


---

#### Markdown Notes

A full Markdown editor integrated directly into IDA. Use it to write and organize your analysis findings for each function.

Key features:

- **Live preview** — toggle between the raw Markdown editor and a rendered preview at any time
- **Formatting toolbar** — one-click buttons for bold, italic, headings, code blocks, bullet lists, and horizontal rules
- **Auto-save to IDB** — notes are saved directly into the IDB file keyed to the function address; no external files needed
- **Per-function scope** — each function has its own note. Notes are restored automatically when you navigate to a function.
- **Export** — notes can be copied as plain Markdown for use in external reports

Typical use cases: documenting what a function does, logging IOCs found, noting questions for later, tracking renamed items.

![ida_2kEzCpNSsB](https://github.com/user-attachments/assets/a4c58be1-c4a5-4b9c-9833-5cc58319f9d4)

---

#### Function Explain

Explain what does the current function do.

<img width="1736" height="957" alt="image" src="https://github.com/user-attachments/assets/860409a0-3481-42c1-bfe8-59173a2f8b29" />


---

#### Tree Graph

Displays a text-based, high-level execution flow graph for the current function, generated by AI.

Unlike a raw call graph, this is a narrative representation of how execution moves through the function — showing decision branches, loops, and the intent behind each block in plain English.

Example output:

```
├─ Attempt to enable debug privileges
│  └─ If enabling debug privileges succeeds
│     ├─ Retrieve the explorer process ID
│     │  └─ If explorer process ID is valid
│     │     ├─ Open the explorer process with required access rights
│     │     │  └─ If process handle is valid
│     │     │     ├─ Obtain the primary token of the explorer process
│     │     │     │  └─ If token retrieval succeeds
│     │     │     │     ├─ Impersonate the logged-on user associated with the token
│     │     │     │     │  └─ If impersonation succeeds
│     │     │     │     │     ├─ Close the token handle
│     │     │     │     │     ├─ Close the process handle
│     │     │     │     │     └─ Return success (1)
│     │     │     │     └─ If impersonation fails
│     │     │     │        ├─ Close the token handle if valid
│     │     │     │        └─ Close the process handle if valid
│     │     │     └─ If token retrieval fails
│     │     │        ├─ Close the process handle if valid
│     │     │        └─ Proceed to failure path
│     │     └─ If process handle is invalid
│     │        └─ Proceed to failure path
│     └─ If explorer process ID is invalid
│        └─ Proceed to failure path
└─ If enabling debug privileges fails
 └─ Return failure (0)
```

This tab is especially useful when the pseudocode is dense or heavily obfuscated and a plain-language summary of the control flow helps orient the analysis.

<img width="1743" height="960" alt="image" src="https://github.com/user-attachments/assets/309a9b70-3240-4143-9c8a-b22e402fcb31" />

---

#### Function Details

Displays contextual metadata gathered from IDA about the currently active function without any AI call.

Shown information:

- **Callers** — functions that call this function, with their addresses
- **Callees (API / Library)** — external API and library functions called from this function (e.g., `CreateFileW`, `VirtualAlloc`)
- **Callees (Internal)** — other user-defined functions called from this function
- **String references** — string literals referenced by instructions in this function
- and more

This tab is useful for quick context gathering before deciding whether to run a deeper AI action.

<img width="1743" height="972" alt="image" src="https://github.com/user-attachments/assets/5b39ea48-a39e-48c1-a80a-ccbe6491e39c" />

---

### Rename Function

**Hotkeys:** `Ctrl+Alt+N` (Code mode) · `Ctrl+Alt+M` (Malware mode)

Sends the current function's decompiled pseudocode to the AI and asks for a meaningful name based on what the code actually does.

- **Code mode** — General-purpose. Focused on the logic and behaviour of the code.
- **Malware mode** — Adds a malware analysis context to the prompt. The AI is aware of TTPs, C2 patterns, evasion techniques, and common malware patterns.

A confirmation dialog appears with the suggested name, confidence score, and a brief rationale. You can accept, edit, or reject the suggestion.

The rename prefix (`fn_` by default) and an optional address suffix can be configured in Settings.

![ida_3PXAhsbh0V](https://github.com/user-attachments/assets/7e786bcc-2bbc-4e01-81f7-017d85a9f526)

---

### Rename Variables

**Hotkey:** `Ctrl+Alt+R`

Sends the decompiled code to the AI, which returns a mapping of old variable names to new semantic names (e.g., `v3 -> socket_fd`, `v12 -> encrypted_buffer`).

The plugin applies all renames directly to the Hex-Rays decompiler using `ida_hexrays.rename_lvar()`. A fallback verification step is used if a rename returns `False` due to stale decompiler caches.

![nyQc7GMToe](https://github.com/user-attachments/assets/a0c9f7c9-0f38-4d35-aea0-1aff5b0feaa9)

---

### Add Comments (Pseudocode)

**Hotkey:** `Ctrl+Alt+C`

The AI reads the decompiled code and adds inline comments at key logic points. Comments are written as Hex-Rays user comments and are also synced with the disassembly view as repeatable comments.

![1Ty7bxrf1Z](https://github.com/user-attachments/assets/6dc8d216-b63d-4017-a028-e8885c22f43e)


---

### Add Section Comments (IDA-View)

**Menu:** `Edit > Plugins > PseudoNote > Add Section Comments (IDA-View)`

Works in the disassembly view. The AI groups instructions into logical sections and provides a short plain-English label for each (e.g., `init stack frame`, `validate argument`, `call export resolver`).

This action also works on a **selection**. Highlight a range of instructions in IDA-View, then trigger the action — only the selected range is sent to the AI. This is particularly useful for analysing embedded shellcode blobs within a larger function.

![ida_WTUgWjwz3o](https://github.com/user-attachments/assets/b84f2d6f-0686-4b62-8294-917d0f737432)

---

### Function Prototype

**Hotkey:** `Ctrl+Alt+S`

The AI infers the function's calling convention, parameter names, parameter types, and return type, then applies the result directly to IDA using `idc.apply_type()`. The generated prototype can be reviewed before applying.

<img width="1058" height="548" alt="image" src="https://github.com/user-attachments/assets/875addac-1671-41a0-a45b-6861fa4aa688" />

---

### Struct Editor

**Access:** Right-click on a variable name in pseudocode > **PseudoNote** > **Struct editor**

Opens a dialog with a blank struct template. Click **AI Suggestion** to have the AI infer the structure layout by analysing all field accesses in the current function and its callers (e.g., `ptr + 0x18`, `v5->field_20`).

You can optionally provide the exact total size of the struct so the AI can calculate padding precisely. After generation you can:

- Edit the definition manually in the code editor
- Copy to Clipboard
- Apply to IDA — parses and imports it into Local Types (`Shift+F1`), then asks if you want to apply the type to the variable

---

### Ask Chat (AI)

**Hotkey:** `Ctrl+Alt+A`

Opens a dockable chat window contextualised to the current function. The AI is pre-loaded with the function's decompiled code so you can ask targeted questions:

- "What API does this function use to achieve persistence?"
- "What does `v7` represent here?"
- "Is this a known decryption algorithm?"
- "Rewrite this in Python."

Chat history is persisted to the IDB per function. When you return to a function, the history is automatically restored. When you navigate to a different function, the chat seamlessly switches context with a notification.

![ida_TPhxGX9F8O](https://github.com/user-attachments/assets/187ea70a-8b8c-424c-ba10-5c6873928cf7)

---

### Bulk Function Renamer

**Hotkey:** `Ctrl+Shift+R`

A batch-renaming tool that can rename hundreds of functions in one session.

Key features:

- Function list with checkboxes to include or exclude specific functions
- Filter to show only unnamed (`sub_*`) functions and hide system/library functions
- Queue system — functions are categorised into `high`, `medium`, `low` priority based on complexity
- Configurable batch size and number of parallel workers
- Preview before apply — review all suggested renames before committing
- Configurable rate-limit cooldown between API batches
- Prefix and address suffix naming style (e.g., `fn_my_function_401000`)

The AI is strictly constrained: it does not invent names without evidence. Functions that only call `sub_*` with no strings or known API evidence receive a `wrap_<offset>` name with a confidence of 30% or below.

![ida_Y6QLFZ9MmN](https://github.com/user-attachments/assets/a48c8595-e76b-42fa-a53f-279aac295131)

---

### Bulk Variable Renamer

**Hotkey:** `Ctrl+Shift+V`

Same batch architecture as the function renamer, but for local variables across many functions.

- Processes functions in configurable batch sizes
- Sends each function's decompiled code to the AI and receives a `{old_name: new_name}` mapping
- Applies renames via `ida_hexrays.rename_lvar()` with a verification fallback
- Shows per-function rename counts and failures in the results table
- Results are stored in the IDB for review after the session

![ida_QTsoEYQ9qc](https://github.com/user-attachments/assets/b803a166-aa5a-441a-a1a6-f8a3b7cfac41)

---

### Bulk Function Analyzer

**Hotkey:** `Ctrl+Shift+A`

A fast triage tool that classifies every function with a malware behaviour tag and confidence percentage, without deep per-function analysis.

Tags include: `malicious`, `suspicious`, `benign`, with sub-categories such as `networking`, `encryption`, `injection`, `persistence`, `file_ops`, `evasion`, and others.

The analyzer uses:

1. Static heuristics — API taxonomy lookup against `malware_api_tags.json` for known-malicious Windows API patterns
2. AI classification — sends decompiled code, strings, and API call list to the AI for a verdict
3. Entropy and complexity scoring — factors in byte entropy and CFG branch count as additional signals
4. Combination rules — detects dangerous API combinations (e.g., `VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread` = process injection)

Results are displayed in a sortable, filterable table. You can filter by tag or double-click to navigate to a function.

![ida_8MKhw3CUJs](https://github.com/user-attachments/assets/d2e6e19b-f559-48c5-98fc-9b8d4e0fcdc0)


---

### Deep Analyzer

**Hotkey:** `Ctrl+Shift+S`

The most powerful feature in PseudoNote. A full recursive, multi-stage analysis pipeline that:

1. Builds a complete call graph from your chosen entry point
2. Renames all functions and variables bottom-up, starting from leaf functions
3. Performs deep per-function AI analysis
4. Uses caller context to upgrade or downgrade risk assessments
5. Generates a comprehensive HTML forensic report

See the [Deep Analyzer Pipeline](#deep-analyzer-pipeline) section below for the full stage-by-stage breakdown.

<img width="1202" height="832" alt="image" src="https://github.com/user-attachments/assets/41756753-5d40-4921-bf2b-b4edefcdd427" />

<img width="1920" height="1032" alt="image" src="https://github.com/user-attachments/assets/e7f387db-f9b5-40ca-82d3-afaca8b263af" />

#### HTML Report Example on PhantomNet sample analysis

<img width="1920" height="945" alt="image" src="https://github.com/user-attachments/assets/f8c7fa05-d871-4047-b62a-8c4a057d9e79" />

<img width="1920" height="945" alt="image" src="https://github.com/user-attachments/assets/4a79b651-629f-40fa-a36c-a5238b266cde" />

<img width="1920" height="945" alt="image" src="https://github.com/user-attachments/assets/503b3369-5d2b-4b97-b063-08eb49e4ac12" />

<img width="1920" height="945" alt="image" src="https://github.com/user-attachments/assets/f5d25464-2aa4-4a32-b7ce-c69f7b4d1a7f" />

<img width="1920" height="945" alt="image" src="https://github.com/user-attachments/assets/12ab4ef4-16b6-4eae-9b7b-169434152e2c" />

<img width="1920" height="945" alt="image" src="https://github.com/user-attachments/assets/f13e3818-685c-44db-ac4e-50208b94e98f" />

<img width="1920" height="945" alt="image" src="https://github.com/user-attachments/assets/b5daa901-ca36-4a83-b3a1-f3e386067f8d" />

<img width="1920" height="945" alt="image" src="https://github.com/user-attachments/assets/627bb726-5882-42d0-a5a4-b6809f147fcd" />

<img width="1920" height="945" alt="image" src="https://github.com/user-attachments/assets/2f7035f8-544d-4964-a53b-a471a283a151" />

<img width="1920" height="945" alt="image" src="https://github.com/user-attachments/assets/c1f2524a-8911-42ef-bc07-292a9c3713eb" />

<img width="1920" height="945" alt="image" src="https://github.com/user-attachments/assets/95c6b2f2-672e-4a16-8349-4454e83f6a28" />

<img width="1920" height="945" alt="image" src="https://github.com/user-attachments/assets/29bd1fc0-5ef4-4ed1-b56e-2170c40c5b08" />


---

### FLOSS Strings Discovery

**Hotkey:** `Ctrl+Shift+F`

Integrates [FLOSS (FLARE Obfuscated String Solver)](https://github.com/mandiant/flare-floss) directly into IDA.

FLOSS finds strings that do not appear in normal string scans because they are:

- **Stack strings** — built character-by-character on the stack
- **Tight strings** — constructed in tight loops
- **Decoded strings** — decrypted or deobfuscated at runtime

**Setup:** Install FLOSS and configure its full path in Settings > External Tools > FLOSS Path.

Results are shown in a tabbed IDA chooser with columns for Type, String value, and Function address. Clicking a result navigates to the relevant function. Results are persisted to the IDB so you do not need to re-run FLOSS every session.

<img width="1041" height="738" alt="image" src="https://github.com/user-attachments/assets/ec2d0b10-c5cc-41aa-84a8-17cf50a89c7c" />

---

### Shellcode Analysis (Static)

**Menu:** `Edit > Plugins > PseudoNote > Shellcode Analysis (Static)`

Opens a static analysis dialog for selected shellcode. Select a byte range in IDA-View before launching — the selected bytes and disassembly are pre-loaded into the dialog. The AI provides a high-level analysis of the shellcode's likely purpose, technique, and target platform.

> Tested primarily with msfvenom-generated shellcode.

<img width="1528" height="915" alt="image" src="https://github.com/user-attachments/assets/e4230ec5-5dc9-4070-bbf3-4f283d1fb6ae" />

---

### Call Highlighter

**Menu:** `Edit > Plugins > PseudoNote > Toggle Call Highlight (Pseudocode / Graph/Linear)`

Highlights function calls visually:

- In pseudocode — highlights any line containing a function call with a light lavender background
- In disassembly — highlights `call` and `jmp` instructions with the same colour

Also highlights any function with a `fn_`, `wrap_`, or `sub_` prefix, making it easy to identify which calls have already been renamed versus which are still unknown.

<img width="1690" height="816" alt="image" src="https://github.com/user-attachments/assets/0b39f11b-453d-4bc4-8bff-fbb3e9fafe83" />

---

### Search Utilities

Available from the right-click context menu in Disassembly or Pseudocode views.

| Action | How to trigger | What it does |
|---|---|---|
| Search Bytes in VirusTotal | Select bytes in IDA-View, right-click | Opens VT content search for the selected hex bytes |
| Add Bytes to CyberChef | Select bytes in IDA-View, right-click | Base64-encodes and opens CyberChef with bytes as input |
| Search String in VirusTotal | Highlight text, right-click | Searches the string as file content in VT |
| Search String in Google | Highlight text, right-click | Exact-phrase Google search |
| Search String in GitHub | Highlight text, right-click | Code search on GitHub |
| Search String (WinAPI) in MSDN | Highlight text, right-click | MSDN Documentation search |
| Add String to CyberChef | Highlight text, right-click | Opens CyberChef with the string as input |

<img width="629" height="440" alt="image" src="https://github.com/user-attachments/assets/8caad3f4-10bb-4a62-afb3-f1674fef02e6" />

> If no text is highlighted when triggering a string search, a prompt dialog appears asking you to type the search term manually.

<img width="725" height="102" alt="image" src="https://github.com/user-attachments/assets/d5568c63-6f5f-4d73-b35d-e4ccda44d6a4" />

---

## Bulk Analyzer vs Deep Analyzer

| Aspect | Bulk Function Analyzer | Deep Analyzer |
|---|---|---|
| Purpose | Fast triage — tag and classify every function | Full forensic analysis from a chosen entry point |
| Scope | Flat list of all functions in the binary | Recursive call graph from your chosen root function |
| Analysis depth | Single-pass AI per function batch | Multi-stage pipeline (7 stages) |
| Call graph | No | Yes, full bottom-up traversal |
| Variable renaming | No | Yes, per-function bottom-up |
| Readable C generation | No | Yes |
| Output | Tag and confidence in UI table; saved to IDB | IDB renames + full HTML report + disk artifacts |
| Speed | Fast (parallelised batches) | Slow (thorough; configurable stages) |
| Best for | Initial triage of an unknown binary | Deep dive into a specific execution path |

**Recommended workflow:**

1. Run **Bulk Function Analyzer** first to get a bird's-eye view and identify suspicious functions.
2. Pick an interesting `malicious`-tagged function as the entry point for the **Deep Analyzer**.
3. Use **Ask Chat** to investigate specific functions in detail.

---

## Deep Analyzer Pipeline

The Deep Analyzer runs in two major phases across 7 stages.

<p align="center">
  <img src="https://github.com/user-attachments/assets/60e76eb6-3960-4c53-aed5-587909f05eff" width="700">
</p>

---

### PHASE 1: Discovery & Preparation

#### Stage 1 — Environment Setup

Initialises workspace directories alongside the IDB, detects the binary path from IDA, validates that the AI is configured, and checks all dependencies. A workspace folder named `DeepAnalyzer_{EntryFunction}_{Filename}_{Timestamp}` is created next to the IDB file.

#### Stage 2 — Recursive Call Graph Discovery

Starting from your chosen entry function, the analyser recursively traverses all callees using IDA's cross-reference engine. It builds a complete `FuncNode` graph with:

- Caller and callee relationships
- Function depth from the entry point
- Library and thunk detection (excluded from deep analysis by default)
- Configurable limits: max nodes, max depth, max callees per node, max queue size

#### Stage 3 — Initial Function & Variable Renaming

Eliminates `sub_XXXXXX` names before the deep analysis begins. Uses a bottom-up approach (leaf functions first) so that by the time a caller is analysed, its callees already have meaningful names.

- Variable rename via the Bulk Variable Renamer pipeline
- Function rename using the same AI prompts as the standalone rename actions
- Configurable prefix (`da_` by default) and optional address suffix

---

### PHASE 2: Deep Malicious Code Analysis

#### Stage 4 — Initial Code Analysis + Readable C Generation

For each function in the call graph, the AI:

- Rewrites the decompiled code into clean, readable C
- Performs a baseline threat assessment (encryption, networking, file I/O, process injection, etc.)
- Assigns an initial risk tag (`malicious`, `suspicious`, `benign`)
- Identifies technical indicators

Generated readable C is saved to `<workspace>/readable/` on disk.

#### Stage 5 — Contextual Code Analysis Refinement

Re-analyses each function with caller context. The AI now knows why a function is being called. This allows:

- Upgrading benign-looking utility functions when called from a malicious context
- Downgrading false positives when the caller context shows legitimate usage
- Propagating behavioural intent up and down the call chain

#### Stage 6 — Report Data Generation

Synthesises all collected analysis data:

- Executive summary
- IOC extraction (IPs, domains, registry keys, file paths, mutex names)
- String categorisation
- MITRE ATT&CK technique mapping
- Mermaid call graph rendering
- Function-level risk heat map

#### Stage 7 — HTML Report Generation

Generates a self-contained styled HTML report saved to `<workspace>/report.html`. The report includes:

- Executive summary with overall risk assessment
- MITRE ATT&CK coverage table
- Per-function analysis cards with readable C, indicators, and risk badges
- IOC table
- String analysis section
- Interactive call graph (Mermaid diagram)

---

## Bulk Function Analyzer Pipeline

<p align="center">
  <img src="https://github.com/user-attachments/assets/d4efc1b8-2c77-4eb3-b8e3-2c66fea86fdd" width="800">
</p>


1. **Load all functions** — scans every defined function in the binary
2. **Filter** — optionally skip system/library functions and functions with no code
3. **Static pre-tagging** — applies the malware API taxonomy without any LLM call; fast heuristic based on API names seen in each function
4. **Batch AI classification** — groups functions into configurable batches, sends decompiled pseudocode, strings, and API call list to the AI
5. **Result application** — updates the tag, confidence, and reason in the UI table and saves to IDB
6. **Retry logic** — failed batches are automatically queued for retry

---

## Data Persistence

PseudoNote stores everything inside the IDA database (IDB file) using IDA's native NetNode mechanism.

- AI analysis, renamed symbols, notes, and chat history survive IDA restarts
- Sharing the IDB with teammates means they see all your annotations
- No external database or server is required for core functionality

| Data | Storage Location | IDB Tag |
|---|---|---|
| Readable C (per function) | IDB NetNode `$ pseudonote:readable_c` | tag 0 |
| Chat history (per function) | IDB NetNode (same node) | tag 90 |
| Variable rename results | IDB NetNode (same node) | tag 91 |
| Analyzer results (tag/confidence) | IDB NetNode (same node) | tag 90 |
| FLOSS string results | IDB NetNode `$ pseudonote:floss_results` | — |
| Analyst notes (Markdown) | IDB NetNode | — |

Deep Analyzer disk artifacts are saved alongside the IDB:

```
<idb_directory>/
└── <binary_name>_pseudonote/
    ├── decomp/          <- raw Hex-Rays decompiled code
    ├── readable/        <- AI-generated readable C
    ├── exec_flow/       <- execution flow text graphs
    └── report.html      <- full forensic HTML report
```

---

## Configuration File Reference

The config is stored at `PseudoNote.ini` in the plugin folder, or `~/.pseudonote.ini` if the plugin folder is not writable.

| Section | Key | Default | Description |
|---|---|---|---|
| `[PseudoNote]` | `PROVIDER` | `openai` | Active AI provider |
| `[Analysis]` | `BULK_BATCH_SIZE` | `10` | Functions per batch (Bulk Renamer) |
| `[Analysis]` | `BULK_WORKERS` | `5` | Parallel worker threads (Bulk Renamer) |
| `[Analysis]` | `BULK_COOLDOWN` | `22` | Seconds between batches |
| `[Analysis]` | `VAR_BATCH_SIZE` | `5` | Functions per batch (Var Renamer) |
| `[Analysis]` | `DEEP_MAX_LINES` | `200` | Max decompiled lines per function (Deep Analyzer) |
| `[Analysis]` | `MAX_GRAPH_NODES` | `500` | Max call graph nodes (Deep Analyzer) |
| `[Analysis]` | `MAX_GRAPH_DEPTH` | `15` | Max call graph depth (Deep Analyzer) |
| `[Analysis]` | `DEEP_VAR_RENAME` | `True` | Enable variable rename in Deep Analyzer |
| `[Analysis]` | `DEEP_FUNC_COMMENT` | `True` | Enable function commenting in Deep Analyzer |
| `[Analysis]` | `DEEP_REFINEMENT` | `True` | Enable Stage 5 contextual refinement |
| `[ExternalTools]` | `FLOSS_PATH` | (empty) | Full path to the floss executable |
| `[Fonts]` | `CODE_FONT` | `Consolas` | Font for code display areas |

---

## Tips & Best Practices

**Start with Bulk Analyzer for orientation**

Before jumping into Deep Analyzer, run the Bulk Analyzer to map which functions are suspicious. This helps you choose a good entry point for the deep analysis.

**Use "Rename Function (Malware)" for malware samples**

The malware-specific prompt gives the AI additional context about TTPs. This often produces more accurate names for functions like loaders, injectors, and C2 communication routines.

**Select shellcode bytes before using Section Comments**

In IDA-View, select a byte range then trigger Section Comments. Only the selected range is sent to the AI — ideal for analysing embedded shellcode blobs within a larger function.

**Chat is your interactive companion**

Use Ask Chat when you are unsure about a specific piece of code. The AI already has the decompiled code as context — ask precise questions like "What is v5 on line 23?" without pasting any code manually.

**Tune batch sizes for your rate limits**

If you hit API rate limits, reduce `BULK_WORKERS` and increase `BULK_COOLDOWN` in settings. For local models (Ollama, LM Studio), you can set `BULK_COOLDOWN=0` and increase workers freely.

**FLOSS results persist**

Once you run FLOSS Strings Discovery, the results are saved to the IDB. Subsequent sessions load from the IDB instantly without re-running FLOSS.

---

## Troubleshooting

| Problem | Likely Cause | Fix |
|---|---|---|
| Plugin does not load | Missing `openai` or `httpx` package | Run `pip install openai httpx` with IDA's Python |
| "AI Provider not configured" | No API key saved | Open Settings, enter key, click Save |
| AI requests time out | Network issue or proxy needed | Set proxy in Settings > PseudoNote tab |
| Variable rename shows failures | Hex-Rays stale decompiler cache | Normal for some variables; a fallback verification step is built in |
| Deep Analyzer crashes on large binaries | Call graph too large | Reduce `MAX_GRAPH_NODES` and `MAX_GRAPH_DEPTH` in Settings |
| FLOSS produces no results | Wrong FLOSS path configured | Verify the `floss` executable path in Settings > External Tools |
| Config not saving | Permission denied on Program Files | Config auto-falls back to `~/.pseudonote.ini` |
| "Hex-Rays not available" on startup | Hex-Rays decompiler not licensed | Features requiring pseudocode (rename, comments) need a Hex-Rays licence |

---

*All AI-generated results should be treated as assistance, not ground truth. Always verify critical findings manually.*
