# Blue-engine-
🔵 Blue Engine
🚀 Overview
Blue Engine is a Python-powered security research tool designed to streamline reconnaissance across multiple platforms. It automates searching for cybersecurity techniques or keywords by querying sources like MITRE ATT&CK, Reddit (/r/netsec), Elastic Security documentation, Medium articles, iRed.Team references, and more. By scoring partial matches with fuzzy logic, Blue Engine makes it super simple to discover high-relevance content for your investigations or threat-hunting engagements.

🛠️ What Does Blue Engine Do?
✅ Automated Searching – Queries various cybersecurity sources with a single keyword or technique name.
✅ Fuzzy Matching – Uses partial match scoring to find relevant links even if the phrasing doesn’t exactly match your search term.
✅ Multi-Source Hunting – Fetches data from MITRE ATT&CK, Reddit, Elastic, Medium, Wazuh, iRed.Team, Root X blog, and Sh3ll blog.
✅ Easy-To-Read Output – Displays a clean, structured list of results with relevance scores.
✅ Cross-Platform Compatibility – Runs on Windows, macOS, and Linux (as long as Python is installed).

📌 Requirements
To run Blue Engine, you need:

Python 3.7+ installed on your system.
pip (Python package manager).
The following Python libraries (install them via pip):
bash
Copy
Edit
pip install requests beautifulsoup4 fuzzywuzzy python-Levenshtein
🔧 Features
💡 Multiple Data Sources – Fetches the most relevant results from cybersecurity blogs, documentation, and social platforms.
🔍 Fuzzy String Matching – Finds approximate matches, making your research more comprehensive.
📊 Configurable Output – Displays up to 10 of the most relevant results (default).
🎯 Customizable Threshold – Adjust the fuzzy matching sensitivity to refine searches.

🚀 Usage
1️⃣ Clone or download this repository and ensure you have Blue Engine.py on your system.
2️⃣ Open your preferred terminal or command prompt.
3️⃣ Navigate to the folder containing Blue Engine.py.
4️⃣ Run the script:

bash
Copy
Edit
python Blue Engine.py
5️⃣ Enter the cybersecurity technique or keyword when prompted.

Example 📝
plaintext
Copy
Edit
> python Blue Engine.py
Enter a cybersecurity technique: powershell obfuscation

🔍 Searching for partial matches of: 'powershell obfuscation' (threshold=40)

🌐 MITRE ATT&CK Results:
   ✅ [score=80] https://attack.mitre.org/techniques/T1059/002
   ✅ [score=72] https://attack.mitre.org/techniques/T1086
   ...
Blue Engine will scan all sources and provide you with highly relevant links for your cybersecurity research!

![image](https://github.com/user-attachments/assets/f34553c0-c802-437e-a3b2-40f8edfd242f)

![image](https://github.com/user-attachments/assets/84d2b819-99bb-4997-98e9-e649998445af)


🤝 Contributions
💙 We welcome issues and pull requests in this GitHub repository! If you:

Found a bug 🐞
Want to add new data sources 📡
Have an enhancement idea 🚀
Feel free to open an issue or submit a pull request!




📌 License
This project is open-source and free to use. Stay curious, and happy threat hunting! 🎯🔍🔥

Let me know if you want any other modifications! 🚀💙
