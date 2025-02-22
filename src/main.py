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

#Radio button selection handler
def on_radio_select():
    if searchV.get() == "1":  # CVE selected
        severity_label.grid(column=0, row=2, sticky=W)
        severity_entry.grid(column=1, row=2, sticky=(W))
    else:  # CPE selected
        severity_label.grid_remove()
        severity_entry.grid_remove()

#Input validation for spinbox
def validate_spinbox(value):
    if value == "":
        return True
    try:
        int_value = int(value) #converting to int value
        return 1 <= int_value <= 100
    except ValueError:
        return False

#Search function which handles both CPE & CVE search
def search_vulnerabilities():
    root.update()

    # Clear previous results
    for i in results_tree.get_children():
        results_tree.delete(i)

    if searchV.get() == "1":  # CVE selected
        service = service_entry.get()
        severity = severity_entry.get().upper()

        if not service:
            results_tree.insert('', 'end', values=("Error: Service field cannot be empty.",))
            return

        valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if severity and severity not in valid_severities:
            results_tree.insert('', 'end',
                                values=("Error: Invalid severity. Please use LOW, MEDIUM, HIGH, or CRITICAL.",))
            return

        try:
            # Perform NVD search
            nvd_query = nvd.searchCVE(keywordSearch=service, cvssV3Severity=severity if severity else None,
                                      key=api_key,limit=limit_var.get())
            print(f"API Response type: {type(nvd_query)}")
            print(f"API Response: {nvd_query}")

            # Display results in the Treeview
            if nvd_query:
                for cve in nvd_query:
                    cve_id = cve.id
                    score = str(cve.score[1]) if cve.score and len(cve.score) > 1 and cve.score[
                        1] is not None else "N/A"
                    references = ", ".join([ref.url for ref in cve.references]) if cve.references else "N/A"
                    results_tree.insert('', 'end', values=(score, cve_id, references))
            else:
                results_tree.insert('', 'end', values=("No results found.",))
        except Exception as e:
            print(f"Error during search: {str(e)}")
            results_tree.insert('', 'end', values=(f"Error during search: {str(e)}",))
    else:
        results_tree.insert('', 'end', values=("CPE search not implemented yet.",))


## GUI Setup
root = tk.Tk()
root.title("vulnerTrack")
root.geometry("800x600")
style = ttk.Style()

# Main Frame using ttk.Frame for padding support
style.configure("Custom.TFrame", background="black")
mainframe = ttk.Frame(root, padding="10 10 10 10", style="Custom.TFrame")
mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

# Radio Buttons for CPE vs CVE
searchV = tk.StringVar(root, "1")

ttk.Radiobutton(mainframe, text="CVE", variable=searchV, value="1", command=on_radio_select).grid(column=0, row=0,
                                                                                                  sticky=W)
ttk.Radiobutton(mainframe, text="CPE", variable=searchV, value="2", command=on_radio_select).grid(column=1, row=0,
                                                                                                  sticky=W)
style.configure("TRadiobutton", background="black", foreground="white")
style.map("TRadiobutton", indicatorcolor=[("selected", "#90EE90"), ("!selected", "white")])

# Service Label and Entry Field
style.configure("Custom.TLabel", foreground="#90EE90", font=("Terminal", 12), background="black")
style.layout("Custom.TEntry", [('Entry.plain.field', {'children': [(
    'Entry.background', {'children': [(
        'Entry.padding', {'children': [(
            'Entry.textarea', {'sticky': 'nswe'})],
        'sticky': 'nswe'})], 'sticky': 'nswe'})],
    'border': '2', 'sticky': 'nswe'})])
style.configure("Custom.TEntry", fieldbackground="black", foreground="#90EE90", font=("Terminal", 12))
service_label = ttk.Label(mainframe, text="Service:", style="Custom.TLabel")
service_label.grid(column=0, row=1, sticky=W)
service_entry = ttk.Entry(mainframe, width=30, style="Custom.TEntry")
service_entry.grid(column=1, row=1, sticky=(W))

# Severity Label and Entry Field (Optional)
severity_label = ttk.Label(mainframe, text="Severity (Optional):", style="Custom.TLabel")
severity_label.grid(column=0, row=2, sticky=W)
severity_entry = ttk.Entry(mainframe, width=30, style="Custom.TEntry")
severity_entry.grid(column=1, row=2, sticky=(W))

# Output limit label and Entry Field
limit_label = ttk.Label(mainframe, text="Limit:", style="Custom.TLabel")
limit_label.grid(column=0, row=3, sticky=W)
limit_var = tk.IntVar(value=5)  # Default value 5

# Spinbox
vcmd = (root.register(validate_spinbox), '%P')
style.map("Custom.TSpinbox", [('Entry.plain.field', {'children': [(
    'Entry.background', {'children': [(
        'Entry.padding', {'children': [(
            'Entry.textarea', {'sticky': 'nswe'})],
        'sticky': 'nswe'})], 'sticky': 'nswe'})],
    'border': '2', 'sticky': 'nswe'})],
             arrowcolor=[
                 ('disabled', 'green'),
                 ('pressed !disabled', 'blue'),
                 ('focus !disabled', 'green'),
                 ('hover !disabled', 'yellow')]
             )
style.configure("Custom.TSpinbox", fieldbackground="black", foreground="#90EE90", font=("Terminal", 12))
limit_spinbox = ttk.Spinbox(
    mainframe,
    from_=1,
    to=100,
    textvariable=limit_var,
    validate="all",
    validatecommand=vcmd,
    width=10,
    style="Custom.TSpinbox"
)
limit_spinbox.grid(column=1, row=3, sticky=(W))



# Search Button
scan_button = ttk.Button(mainframe, text="Search", command=search_vulnerabilities)
scan_button.grid(column=2, row=5, sticky=W)

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

on_radio_select()

## Run the application
root.mainloop()
