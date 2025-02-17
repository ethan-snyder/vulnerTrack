## Imports
import os
import tkinter as tk
from tkinter import N, W, E, S
from tkinter import ttk
from dotenv import load_dotenv
import nvdlib as nvd

# Load environment variables from .env file
load_dotenv()

# Establishing API Key
api_key = os.getenv('API_KEY')

if not api_key:
    raise ValueError("API key not found. Make sure it's stored in the .env file or set as an environment variable.")


def search_vulnerabilities():
    service = service_entry.get()
    severity = severity_entry.get().upper()

    if not service:
        results_tree.insert('', 'end', values=("Error: Service field cannot be empty.",))
        return

    valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if severity and severity not in valid_severities:
        results_tree.insert('', 'end', values=("Error: Invalid severity. Please use LOW, MEDIUM, HIGH, or CRITICAL.",))
        return

    try:
        # Perform NVD search
        nvd_query = nvd.searchCVE(keywordSearch=service, cvssV3Severity=severity if severity else None, key=api_key,
                                  limit=5)

        # Clear previous results
        for i in results_tree.get_children():
            results_tree.delete(i)

        # Display results in the Treeview
        if nvd_query:
            for cve in nvd_query:
                cve_id = cve.id
                score = str(cve.score[1]) if cve.score[1] is not None else "N/A"

                references = ", ".join([ref.url for ref in cve.references]) if cve.references else "N/A"

                results_tree.insert('', 'end', values=(score, cve_id, references))
        else:
            results_tree.insert('', 'end', values=("No results found.",))
    except Exception as e:
        results_tree.insert('', 'end', values=(f"Error during search: {e}",))


## GUI Setup
root = tk.Tk()
root.title("vulnerTrack")
root.geometry("1000x800")
style = ttk.Style()

# Main Frame using ttk.Frame for padding support
style.configure("Custom.TFrame", background="black")
mainframe = ttk.Frame(root, padding="10 10 10 10", style="Custom.TFrame")
mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

# Radio Buttons for CPE vs CVE
searchV = tk.StringVar(root, "1")

tk.Radiobutton(mainframe, text="CPE", padx=20, variable=searchV, value=1, bg="black", fg="white").grid(column=0, row=0, sticky=W)
tk.Radiobutton(mainframe, text="CVE", padx=20, variable=searchV, value=2, bg="black", fg="white").grid(column=1, row=0, sticky=W)

# Service Label and Entry Field
style.configure("Custom.TLabel", foreground="#90EE90", font=("Terminal", 12), background="black")
service_label = ttk.Label(mainframe, text="Service:", style="Custom.TLabel")
service_label.grid(column=0, row=1, sticky=W)
service_entry = ttk.Entry(mainframe, width=30)
service_entry.grid(column=1, row=1, sticky=(W, E))

# Severity Label and Entry Field (Optional)
severity_label = ttk.Label(mainframe, text="Severity (Optional):", style="Custom.TLabel")
severity_label.grid(column=0, row=2, sticky=W)
severity_entry = ttk.Entry(mainframe, width=30)
severity_entry.grid(column=1, row=2, sticky=(W, E))

# Search Button
scan_button = ttk.Button(mainframe, text="Search", command=search_vulnerabilities)
scan_button.grid(column=1, row=3, sticky=W)

# Results Treeview
results_tree = ttk.Treeview(mainframe, columns=('Score', 'CVE ID', 'References'), show='headings', height=10)
results_tree.grid(row=4, column=0, columnspan=3, sticky=(N, W, E, S))

# Configure the Treeview columns
results_tree.heading('Score', text='Score')
results_tree.heading('CVE ID', text='CVE ID')
results_tree.heading('References', text='References')
results_tree.column('Score', width=100, anchor='center')
results_tree.column('CVE ID', width=150, anchor='center')
results_tree.column('References', width=350, anchor='w')

# Add a scrollbar
scrollbar = ttk.Scrollbar(mainframe, orient="vertical", command=results_tree.yview)
scrollbar.grid(row=4, column=3, sticky=(N, S))
results_tree.configure(yscrollcommand=scrollbar.set)

# Configure grid weights
mainframe.columnconfigure(1, weight=1)
mainframe.rowconfigure(4, weight=1)

# Padding for all child widgets inside mainframe
for child in mainframe.winfo_children():
    child.grid_configure(padx=5, pady=5)

## Run the application
root.mainloop()
