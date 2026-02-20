# PseudoNote Installation

### 1. Copy Files
Copy `PseudoNote.py` and the `pseudonote/` folder into your IDA `plugins` directory.

### 2. Install Dependencies
Run this in your terminal:
```bash
pip install openai httpx
```

### 3. Set API Key

Option, you also can do this in the settings menu in PseudoNote pane

1. Open `pseudonote/PseudoNote.ini`.
2. Set your `PROVIDER` (OpenAI, Anthropic, DeepSeek, etc.) and `MODEL`.
3. Add your `API_KEY` and `BASE_URL` in the corresponding section.

### 4. Use
- **Ctrl+Alt+G**: Open PseudoNote panes.
- **Right-Click**: See options in Pseudocode/Disassembly.
