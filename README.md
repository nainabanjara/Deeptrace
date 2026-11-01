# DeepTrace

A beginner-friendly, responsive digital safety investigation web app built with Python Flask and SQLite.

## Features
- Link scanner with basic URL pattern checks and a simple live website response check
- Message checker for common scam warning signs
- Domain investigator with DNS lookup
- SQLite database for saved investigations
- Report details, scan history, search/filter, delete and text export
- Responsive pages for phones and laptops
- Beginner guide and About page

## Requirements
- Python 3.10 or newer
- Visual Studio Code
- Internet connection for installing Flask and for live link/DNS checks

## Run in VS Code
1. Extract the `DeepTrace` folder.
2. Open VS Code.
3. Select **File > Open Folder** and choose the `DeepTrace` folder.
4. Open the VS Code terminal (**Terminal > New Terminal**).
5. Create a virtual environment (recommended):
   - Windows: `py -m venv .venv`
   - Mac/Linux: `python3 -m venv .venv`
6. Activate it:
   - Windows PowerShell: `.venv\Scripts\Activate.ps1`
   - Windows Command Prompt: `.venv\Scripts\activate.bat`
   - Mac/Linux: `source .venv/bin/activate`
7. Install Flask: `python -m pip install -r requirements.txt`
8. Run: `python app.py`
9. Open `http://127.0.0.1:5000` in your laptop browser.

The SQLite database file `deeptrace.db` is created automatically the first time the app starts.

## Open on your phone
Your phone and laptop must be connected to the same Wi-Fi network.
1. Find your laptop's local IPv4 address:
   - Windows: open Command Prompt and run `ipconfig`; look for **IPv4 Address** under your active Wi-Fi adapter.
   - Mac: System Settings > Wi-Fi > Details, or use `ifconfig`.
2. On your phone, open a browser and enter `http://LAPTOP-IP:5000` (replace LAPTOP-IP with the address you found, for example `http://192.168.1.5:5000`).
3. If Windows Firewall asks, allow Python on your private network only.
4. Keep the laptop and Flask app running while using the site on your phone.

## Run without typing the run command
After installing Flask once, open `app.py` in VS Code and click the small **Run Python File** button in the top-right corner. The app will start in the VS Code terminal. The terminal must remain open while the website is running.

## Important project limitations
- The risk score is based on simple educational rules, not a certified threat-intelligence engine.
- A low score does not prove that a link or message is safe.
- The live link check sends a basic HTTP HEAD request to the URL you enter. Only test public links you have a reason to inspect.
- DNS results depend on the network and domain configuration.
- Message text is stored in the local SQLite database with its report. Do not paste passwords, OTPs, bank details or private conversations.
- This starter project does not include user accounts or cloud hosting. It is intended to run locally for development and college demonstration.
- The project does not crawl websites, break into accounts, or identify private people.

## Suggested next upgrades
- Add user login and separate investigation records per user.
- Integrate a reputable URL reputation API with an API key stored in environment variables.
- Add PDF export.
- Add an admin view and configurable risk rules.
- Add a PWA manifest and install prompt.
\n\n## Photo checker (added)\n- Upload JPG/JPEG/PNG/WEBP images up to 8 MB.\n- Reads dimensions, format, SHA-256 and selected EXIF metadata.\n- Creates a JPEG recompression comparison preview for JPEG images.\n- Saves the investigation in SQLite and supports report/history pages.\n- This is not a trained AI-image detector. It reports file clues only and never claims that a picture is definitely AI-generated or fake.\n\nInstall dependencies from the project folder:\n```powershell\npython -m pip install -r requirements.txt\npython app.py\n```\nOpen `http://127.0.0.1:5000`. For phone testing, use the laptop's local network IP on the same trusted Wi-Fi. Stop the server with Ctrl+C. The built-in Flask server is for local student testing only, not public deployment.\n