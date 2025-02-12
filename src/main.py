# Imports
import os
import tkinter as tk
from tkinter import N, W, E, S, Label, Entry, Button
from tkinter import ttk
from dotenv import load_dotenv
import nvdlib as nvd

# Load environment variables from .env file
load_dotenv()

# Establishing API Key
api_key = os.getenv('API_KEY')

if not api_key:
    raise ValueError("API key not found. Make sure it's stored in the .env file or set as an environment variable.")


# Function to handle NVD search and display results
def search_vulnerabilities():
    service = service_entry.get()
    severity = severity_entry.get()

    if not service:
        results_text.insert(tk.END, "Error: Service field cannot be empty.\n")
        return

    try:
        # Perform NVD query using nvdlib
        nvd_query = nvd.searchCPE(keywordSearch=service, key=api_key, limit=5)

        # Clear previous results
        results_text.delete(1.0, tk.END)

        # Display results in the text widget
        if nvd_query:
            results_text.insert(tk.END, f"Search Results for Service: {service}\n")
            for result in nvd_query:
                results_text.insert(tk.END, f"CPE Name: {result.cpeName}\n")
        else:
            results_text.insert(tk.END, "No results found.\n")
    except Exception as e:
        results_text.insert(tk.END, f"Error during search: {e}\n")


# GUI Setup
root = tk.Tk()
root.title("vulnerTrack")

# Main Frame using ttk.Frame for padding support
mainframe = ttk.Frame(root, padding="10 10 10 10")
mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

# Service Label and Entry Field
service_label = ttk.Label(mainframe, text="Service:")
service_label.grid(column=0, row=0, sticky=W)
service_entry = ttk.Entry(mainframe, width=30)
service_entry.grid(column=1, row=0, sticky=(W, E))

# Severity Label and Entry Field (Optional)
severity_label = ttk.Label(mainframe, text="Severity (Optional):")
severity_label.grid(column=0, row=1, sticky=W)
severity_entry = ttk.Entry(mainframe, width=30)
severity_entry.grid(column=1, row=1, sticky=(W, E))


# Search Button
scan_button = ttk.Button(mainframe, text="Search", command=search_vulnerabilities)
scan_button.grid(column=1, row=2, sticky=W)

# Top labels for output
service_output_label = ttk.Label(mainframe, text="Service", font=("Arial", 14))
service_output_label.grid(column=0, row=3, columnspan=2, sticky=(W, E), pady=(10, 5))
service_output_label = ttk.Label(mainframe, text="Severity", font=("Arial", 14))
service_output_label.grid(column=1, row=3, columnspan=2, sticky=(W, E), pady=(10, 5))
service_output_label = ttk.Label(mainframe, text="References", font=("Arial", 14))
service_output_label.grid(column=2, row=3, columnspan=2, sticky=(W, E), pady=(10, 5))




# Results Text Widget with Scrollbar
results_text = tk.Text(mainframe, width=60, height=20)
results_text.grid(column=0, row=4, columnspan=3, sticky=(W, E))

scrollbar = ttk.Scrollbar(mainframe, orient="vertical", command=results_text.yview)
scrollbar.grid(column=3, row=4, sticky=(N, S))
results_text["yscrollcommand"] = scrollbar.set

# Padding for all child widgets inside mainframe
for child in mainframe.winfo_children():
    child.grid_configure(padx=5, pady=5)

# Run the application
root.mainloop()
