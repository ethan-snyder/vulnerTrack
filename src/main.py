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

## Function to handle NVD search and display results
def search_vulnerabilities():
    if searchV == 1:
        return
    else:
        service = service_entry.get()
        severity = severity_entry.get().upper()
        if not service:
            results_text.insert(tk.END, "Error: Service field cannot be empty.\n")
            return
        valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if severity and severity not in valid_severities:
            results_text.insert(tk.END, "Error: Invalid severity. Please use LOW, MEDIUM, HIGH, or CRITICAL.\n")
            return
        try:

            # Perform NVD search
            nvd_query = nvd.searchCVE(keywordSearch=service, cvssV3Severity=severity if severity else None, key=api_key,
                                      limit=5)
            results_text.delete(1.0, tk.END)  # Clear previous results

            # Display results in the text widget
            if nvd_query:
                results_text.insert(tk.END, f"Search Results for Service: {service}\n\n")
                for result in nvd_query:
                    cve_id = result.id
                    score = result.score if hasattr(result, 'score') else "N/A"

                    # Format the output with tabs to align columns
                    output = f"{score}\t{cve_id}\n"
                    results_text.insert(tk.END, output)
            else:
                results_text.insert(tk.END, "No results found.\n")
        except Exception as e:
            results_text.insert(tk.END, f"Error during search: {e}\n")

## GUI Setup
root = tk.Tk()
root.title("vulnerTrack")
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

# Service Label and Entry Field for CVE
style.configure("Custom.TLabel", foreground="#90EE90", font=("Terminal", 12), background="black")
service_label = ttk.Label(mainframe, text="Service:", style="Custom.TLabel")
service_label.grid(column=0, row=1, sticky=W)
service_entry = ttk.Entry(mainframe, width=30)
service_entry.grid(column=1, row=1, sticky=(W, E))

# Service Label and Entry Field for CPE
keyword_label = ttk.Label(mainframe, text="Keyword:", style="Custom.TLabel")
keyword_label.grid()
deprecated_label = ttk.Label(mainframe, text="Deprecated:", style="Custom.TLabel")
deprecated_label.grid()
# deprecated checkbox
is_deprecated = tk.IntVar()
deprecated_checkbox = ttk.Checkbutton(mainframe, text="Deprecated", variable=is_deprecated, onvalue=1, offvalue=0)
deprecated_checkbox.grid().pack()


# Severity Label and Entry Field (Optional)
severity_label = ttk.Label(mainframe, text="Severity (Optional):", style="Custom.TLabel")
severity_label.grid(column=0, row=2, sticky=W)
severity_entry = ttk.Entry(mainframe, width=30)
severity_entry.grid(column=1, row=2, sticky=(W, E))

# Search Button
scan_button = ttk.Button(mainframe, text="Search", command=search_vulnerabilities)
scan_button.grid(column=1, row=3, sticky=W)

# Top labels for output
score_output_label = ttk.Label(mainframe, text="Score", style="Custom.TLabel")
score_output_label.grid(column=0, row=4, sticky=(W, E), pady=(10, 5))
cve_output_label = ttk.Label(mainframe, text="CVE ID", style="Custom.TLabel")
cve_output_label.grid(column=1, row=4, sticky=(W, E), pady=(10, 5))
service_output_label = ttk.Label(mainframe, text="References", style="Custom.TLabel")
service_output_label.grid(column=2, row=4, sticky=(W, E), pady=(10, 5))

## Results Text Widget with Scrollbar
output_frame = tk.Frame(mainframe, bg="black") # Nested frame for output
output_frame.grid(row=5, column=0, columnspan=3, sticky=(N, W, E, S))

results_text = tk.Text(output_frame, width=60, height=20, bg="black", fg="white")
results_text.grid(column=0, row=0, sticky=(N, S, W, E))

scrollbar = ttk.Scrollbar(output_frame, orient="vertical", command=results_text.yview)
scrollbar.grid(column=1, row=0, sticky=(N, S))
results_text["yscrollcommand"] = scrollbar.set

# Configure grid weights
output_frame.columnconfigure(0, weight=1)
output_frame.rowconfigure(0, weight=1)

# Padding for all child widgets inside mainframe
for child in mainframe.winfo_children():
    child.grid_configure(padx=5, pady=5)

## Run the application
root.mainloop()